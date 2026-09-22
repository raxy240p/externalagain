#include "Esp.hpp"
#include <skCrypter/skCrypter.hpp>
#include "core/engine/DebugEsp.hpp"
#include "core/engine/Engine.hpp"
#include "core/offsets/Offsets.hpp"
#include "core/engine/classes/Game.hpp"
#include <chrono>
#include <cmath>
#include <vector>
#include <Windows.h>   // SendInput, GetAsyncKeyState, INPUT, VK_* for triggerbot
#include "gui/renderer/Renderer.hpp"

// ── Triggerbot ─────────────────────────────────────────────────────────────
// SendInput MOUSE1 pulse when the crosshair overlaps a bone in the selected
// zone on an alive enemy. Runs from Esp::RenderImpl inside the per-player
// loop, which already has the fresh view matrix + bones in scope — zero
// extra work on the read-side. The bound key is polled via
// GetAsyncKeyState (works for keyboard + mouse VK codes).
//
// VAC-hardening on the input side:
//  • DOWN and UP are SPLIT across frames — DOWN fires now, UP is deferred
//    to a randomized 30..70 ms later via s_pendingUp; each frame we drain
//    the deferred UP before doing any new hit-test. Two SendInput calls
//    with a natural human-click hold time in between instead of a
//    zero-gap DOWN+UP batch (the classic external-triggerbot signature).
//  • Inter-shot delay is JITTERED — configured delay_ms is a floor, we
//    add rand(0..delay_ms/2) so consecutive shots never land at a
//    perfectly periodic beat. cfg::delay_ms remains the minimum, so
//    the user's cooldown intent still holds.
//  • While a click is mid-hold (s_pendingUp set) NO new hit-test runs,
//    so we never queue a second DOWN on top of an unresolved UP.
//  • Hold window (30..70 ms) is inside "one CS weapon shot" for even
//    the fastest RPM (Negev @ 700 RPM = 85 ms between shots), so one
//    trigger fire = one bullet regardless of weapon fire mode.
namespace trig {
	static std::chrono::steady_clock::time_point s_lastShot{};
	static std::chrono::steady_clock::time_point s_pendingUp{};   // {} = no click in flight
	static std::chrono::steady_clock::time_point s_nextAllowed{}; // cooldown gate

	// 32-bit LCG for cheap per-frame jitter. Seeded from the process
	// clock the first time it's used; not cryptographic, doesn't need to be.
	static uint32_t s_rng = 0;
	static uint32_t Rand32() {
		if (!s_rng) s_rng = (uint32_t)std::chrono::steady_clock::now()
			.time_since_epoch().count() ^ 0x9E3779B9u;
		s_rng = s_rng * 1664525u + 1013904223u;
		return s_rng;
	}
	// integer in [lo, hi]
	static int RandRange(int lo, int hi) {
		if (hi <= lo) return lo;
		return lo + int(Rand32() % uint32_t(hi - lo + 1));
	}

	// ImGuiKey → Win32 VK. Keyboard rows are dense in ImGui's enum; letter
	// keys and digits map linearly. Mouse buttons and the special row use
	// hand-mapped constants. Anything unknown returns 0 = no fire.
	static int ImKeyToVK(int k) {
		if (k >= ImGuiKey_A && k <= ImGuiKey_Z)         return 'A' + (k - ImGuiKey_A);
		if (k >= ImGuiKey_0 && k <= ImGuiKey_9)         return '0' + (k - ImGuiKey_0);
		if (k >= ImGuiKey_F1 && k <= ImGuiKey_F12)      return VK_F1 + (k - ImGuiKey_F1);
		switch (k) {
			case ImGuiKey_MouseLeft:    return VK_LBUTTON;
			case ImGuiKey_MouseRight:   return VK_RBUTTON;
			case ImGuiKey_MouseMiddle:  return VK_MBUTTON;
			case ImGuiKey_MouseX1:      return VK_XBUTTON1;
			case ImGuiKey_MouseX2:      return VK_XBUTTON2;
			case ImGuiKey_Space:        return VK_SPACE;
			case ImGuiKey_LeftShift:    return VK_LSHIFT;
			case ImGuiKey_RightShift:   return VK_RSHIFT;
			case ImGuiKey_LeftCtrl:     return VK_LCONTROL;
			case ImGuiKey_RightCtrl:    return VK_RCONTROL;
			case ImGuiKey_LeftAlt:      return VK_LMENU;
			case ImGuiKey_RightAlt:     return VK_RMENU;
			case ImGuiKey_CapsLock:     return VK_CAPITAL;
			case ImGuiKey_Tab:          return VK_TAB;
			case ImGuiKey_Insert:       return VK_INSERT;
			case ImGuiKey_Home:         return VK_HOME;
			case ImGuiKey_End:          return VK_END;
			default:                    return 0;
		}
	}

	// Bones per zone. Any bone with zero pos is skipped by BoneValid.
	static const int kHeadBones[]  = { bone_index::head };
	static const int kBodyBones[]  = { bone_index::neck, bone_index::chest,
	                                    bone_index::spine_2, bone_index::spine_1,
	                                    bone_index::pelvis };
	static const int kLegBones[]   = { bone_index::hip_L,  bone_index::knee_L,
	                                    bone_index::foot_heel_L,
	                                    bone_index::hip_R,  bone_index::knee_R,
	                                    bone_index::foot_heel_R };
	static const int kAllBones[]   = { bone_index::head, bone_index::neck,
	                                    bone_index::chest, bone_index::spine_2,
	                                    bone_index::spine_1, bone_index::pelvis,
	                                    bone_index::hip_L, bone_index::knee_L,
	                                    bone_index::foot_heel_L,
	                                    bone_index::hip_R, bone_index::knee_R,
	                                    bone_index::foot_heel_R };

	static void ZoneBones(int zone, const int*& out, int& n) {
		switch (zone) {
			case 0: out = kHeadBones; n = (int)std::size(kHeadBones); return;
			case 1: out = kBodyBones; n = (int)std::size(kBodyBones); return;
			case 2: out = kLegBones;  n = (int)std::size(kLegBones);  return;
			default: out = kAllBones; n = (int)std::size(kAllBones);  return;
		}
	}

	// LMB DOWN half — a single-entry SendInput call. Split from the UP so
	// the two events don't ship as a zero-interval batch (that pattern is
	// the classic external-triggerbot fingerprint on the input side).
	static void FireDown() {
		INPUT in{};
		in.type = INPUT_MOUSE;
		in.mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
		SendInput(1, &in, sizeof(INPUT));
	}
	// LMB UP half — dispatched later by the frame loop when s_pendingUp
	// deadline passes, mimicking natural human click-release latency.
	static void FireUp() {
		INPUT in{};
		in.type = INPUT_MOUSE;
		in.mi.dwFlags = MOUSEEVENTF_LEFTUP;
		SendInput(1, &in, sizeof(INPUT));
	}
}

bool Esp::Init()   { return GetInstance().InitImpl();   }
void Esp::Render() { return GetInstance().RenderImpl(); }

bool Esp::InitImpl() {
	ImFontConfig fcfg{};
	fcfg.FontDataOwnedByAtlas = false;
	this->font = ImGui::GetIO().Fonts->AddFontFromFileTTF(
		skCrypt("C:\\Windows\\Fonts\\consola.ttf"), 12.0f, &fcfg);
	return this->font != nullptr;
}

// ── helpers ───────────────────────────────────────────────────────────────────

static inline ImU32 MakeCol(ImColor c) { return (ImU32)c; }

static inline bool BoneValid(const Vec3_t& b) {
	return (b.x != 0.f) | (b.y != 0.f) | (b.z != 0.f);
}

static inline float HalfX(const std::pair<Vec2_t,Vec2_t>& r) {
	return r.first.x + (r.second.x - r.first.x) * 0.5f;
}

static inline ImVec2 RightFlagPos(const std::pair<Vec2_t,Vec2_t>& b, int row, float ts) {
	float step = ts + 3.f;
	return ImVec2(b.second.x + 4.f, b.first.y + row * step);
}

// ── RenderImpl ────────────────────────────────────────────────────────────────

void Esp::RenderImpl() {
	if (!cfg::enabled) return;

	auto snap      = Cache::CopySnapshot();
	auto& game     = snap.game;
	auto& local    = snap.local;
	auto& players  = snap.players;

	ImGui::PushFont(this->font);
	this->io  = ImGui::GetIO();
	this->d   = ImGui::GetBackgroundDrawList();

	// Read the view matrix fresh on this render frame so fast mouse movement
	// doesn't cause ESP to lag behind the camera. The PA is already cached by
	// the cache thread so this is just a single cheap IOCTL (no PA walk needed).
	{
		auto rp = Engine::GetProcess();
		auto rc = Engine::GetClient();
		if (rp) {
			uintptr_t vmVa = offsets::resolvedViewMatrixVA
			    ? offsets::resolvedViewMatrixVA
			    : (rc.base + offsets::viewMatrix);
			view_matrix_t freshVm{};
			if (rp->read_raw_cached(vmVa, &freshVm, sizeof(freshVm))) {
				float mag2 = freshVm.matrix[0][0]*freshVm.matrix[0][0]
				           + freshVm.matrix[0][1]*freshVm.matrix[0][1]
				           + freshVm.matrix[0][2]*freshVm.matrix[0][2];
				if (mag2 > 0.1f)
					game.view_matrix = freshVm;
			}
		}
	}
	this->matrix = game.view_matrix;

	using clk = std::chrono::steady_clock;
	auto now = clk::now();
	float predDt = std::chrono::duration_cast<std::chrono::microseconds>(
		now - snap.captured).count() * 1e-6f;
	if (predDt < 0.f)  predDt = 0.f;
	if (predDt > 0.02f) predDt = 0.02f;

	// Triggerbot precondition — computed once per frame so the per-player loop
	// stays branch-light. All gates must pass:
	//   • cfg on
	//   • menu NOT open (so a held key never sprays while adjusting settings)
	//   • CS2 IS the foreground window (never fire into another app on alt-tab)
	//   • ImGui isn't capturing the mouse (menu closed but a stray tooltip up)
	//   • local snapshot exists and local is alive
	//   • bound key is currently held (GetAsyncKeyState — polls the OS input
	//     state directly, works whether CS2 or the overlay has focus)
	//   • not blinded, when Ignore Flashed is on
	const bool triggerActive = [&]() -> bool {
		if (!cfg::esp::trigger::enabled) return false;
		if (Renderer::IsOpen())          return false;  // menu open -> never fire
		if (this->io.WantCaptureMouse)   return false;
		if (!local.localplayer)          return false;  // local snapshot not populated yet
		if (!local.alive)                return false;
		int vk = trig::ImKeyToVK(cfg::esp::trigger::key);
		if (!vk)                          return false;
		if (!(GetAsyncKeyState(vk) & 0x8000)) return false;
		if (cfg::esp::trigger::ignore_flashed && local.flashed) return false;
		// CS2 must own the foreground; if the process handle isn't up yet or
		// the hwnd hasn't been resolved, err on the safe side and don't fire.
		auto proc = Engine::GetProcess();
		if (!proc || !proc->hwnd_) return false;
		if (GetForegroundWindow() != proc->hwnd_) return false;
		return true;
	}();

	// Drain any pending UP from a previous frame's click — do this every
	// frame regardless of triggerActive, so a click-in-flight completes
	// even if the user releases the trigger key mid-hold.
	if (trig::s_pendingUp.time_since_epoch().count() != 0 && now >= trig::s_pendingUp) {
		trig::FireUp();
		trig::s_pendingUp = {};
	}
	const bool midClick = (trig::s_pendingUp.time_since_epoch().count() != 0);

	// Cache screen center + zone bone table so the loop just reads
	const float scrCx = io.DisplaySize.x * 0.5f;
	const float scrCy = io.DisplaySize.y * 0.5f;
	const int*  zoneBones = nullptr;
	int         zoneN     = 0;
	if (triggerActive) trig::ZoneBones(cfg::esp::trigger::zone, zoneBones, zoneN);
	const float hitR2 = cfg::esp::trigger::hit_radius_px * cfg::esp::trigger::hit_radius_px;

#ifdef _DEBUG
	{
		static int s_espFrame = 0;
		if (++s_espFrame % 300 == 1) {
			int alive_cnt = 0;
			for (auto& _p : players) if (_p.alive && !_p.localplayer) alive_cnt++;
			printf("[ESP] local.team=%d players=%zu alive_not_local=%d\n",
			       (int)local.team, players.size(), alive_cnt);
		}
	}
#endif

	for (size_t i = 0; i < players.size(); ++i) {
		const Player& raw = players[i];

		if (!g_debugForceEspDraw) {
			if (!raw.alive || raw.localplayer) continue;
		}

		// Only classify as teammate when our team is known; when team==0 (round
		// transition / startup) treat everyone as enemy so ESP doesn't vanish.
		const bool mate = (local.team != 0 && raw.team == local.team);

		if (!g_debugForceEspDraw) {
			if (!cfg::esp::team && mate)                    continue;
			if (cfg::esp::spotted && !raw.spotted)          continue;
			if (local.observer_services.target == raw.pawn_controller_addr
				&& local.observer_services.mode == ObserverMode::First) continue;
		}

		Player pred = raw;
		const float vx = raw.vel.x, vy = raw.vel.y, vz = raw.vel.z;
		const float spd2 = vx*vx + vy*vy + vz*vz;
		if (spd2 > 900.f) {
			pred.pos.x += raw.vel.x * predDt;
			pred.pos.y += raw.vel.y * predDt;
			pred.pos.z += raw.vel.z * predDt;
			for (size_t b = 0; b < pred.bone_list.size(); ++b) {
				pred.bone_list[b].pos.x += raw.vel.x * predDt;
				pred.bone_list[b].pos.y += raw.vel.y * predDt;
				pred.bone_list[b].pos.z += raw.vel.z * predDt;
			}
		}

		if (local.index >= 0 && local.index < 64)
			pred.spotted = (raw.spotted_by_mask >> local.index) & 1u;

		// Triggerbot check — never during a mid-click (avoids DOWN-on-DOWN),
		// never on mates, only on alive targets. Uses PREDICTED bones so
		// fast-strafing enemies don't slip through the hit test. Cooldown
		// is gated by s_nextAllowed which carries the current-shot jitter.
		if (triggerActive && !mate && pred.alive && !midClick && now >= trig::s_nextAllowed) {
			for (int bi = 0; bi < zoneN; ++bi) {
				int idx = zoneBones[bi];
				if (idx < 0 || idx >= (int)pred.bone_list.size()) continue;
				const Vec3_t& bp = pred.bone_list[idx].pos;
				if (!BoneValid(bp)) continue;
				Vec2_t sp;
				if (!matrix.wts(bp, io.DisplaySize, sp)) continue;
				float dx = sp.x - scrCx;
				float dy = sp.y - scrCy;
				if (dx*dx + dy*dy <= hitR2) {
					// FIRE — DOWN now, UP deferred to a randomized human-
					// scale hold time so no zero-gap DOWN+UP batch shows
					// up on any input-side monitor.
					trig::FireDown();
					int holdMs = trig::RandRange(30, 70);
					trig::s_pendingUp = now + std::chrono::milliseconds(holdMs);
					// Next allowed shot = configured floor + [0..floor/2] jitter
					int jitterMax = cfg::esp::trigger::delay_ms / 2;
					if (jitterMax < 1) jitterMax = 1;
					int effectiveDelay = cfg::esp::trigger::delay_ms
						+ trig::RandRange(0, jitterMax);
					trig::s_nextAllowed = now + std::chrono::milliseconds(effectiveDelay);
					trig::s_lastShot    = now;
					break;
				}
			}
		}

		RenderPlayerTracers(local, pred, mate);
		RenderPlayer(pred, mate);
	}

	RenderCrosshair(local);
	ImGui::PopFont();
}

// ── per-player ────────────────────────────────────────────────────────────────

void Esp::RenderPlayer(Player player, bool mate) {
	if (!player.alive) return;

	std::pair<Vec2_t, Vec2_t> bounds;
	if (!player.GetBounds(matrix, io.DisplaySize, bounds)) return;

	if (cfg::esp::box) {
		const bool spotted = cfg::esp::spotted_color && player.spotted;
		ImColor col = mate      ? cfg::esp::colors::box_team
		            : spotted   ? cfg::esp::colors::box_spotted
		                        : cfg::esp::colors::box_enemy;
		d->AddRect(bounds.first, bounds.second, MakeCol(col),
			0.f, 0, cfg::esp::box_thickness);
	}

	RenderPlayerBars(player, bounds);

	if (cfg::esp::skeleton)     RenderPlayerBones(player, mate);
	if (cfg::esp::head_tracker) RenderPlayerTracker(player, bounds, mate);

	RenderPlayerFalgs(player, bounds, mate);
}

void Esp::RenderPlayerBones(Player player, bool mate) {
	ImU32 col = MakeCol(mate ? cfg::esp::colors::skeleton_team
	                         : cfg::esp::colors::skeleton_enemy);
	const float thick = cfg::esp::skeleton_thickness;

	for (size_t k = 0; k < std::size(connections); ++k) {
		const int ai = connections[k][0], bi = connections[k][1];
		const Vec3_t& pa = player.bone_list[ai].pos;
		const Vec3_t& pb = player.bone_list[bi].pos;
		if (!BoneValid(pa) || !BoneValid(pb)) continue;

		Vec2_t sa, sb;
		if (!matrix.wts(pa, io.DisplaySize, sa)) continue;
		if (!matrix.wts(pb, io.DisplaySize, sb)) continue;
		d->AddLine(sa, sb, col, thick);
	}
}

void Esp::RenderPlayerTracker(Player player, std::pair<Vec2_t, Vec2_t> bounds, bool mate) {
	const Vec3_t& hp = player.bone_list[bone_index::head].pos;
	if (!BoneValid(hp)) return;

	Vec2_t head;
	if (!matrix.wts(hp, io.DisplaySize, head)) return;

	const float radius = (bounds.second.x - bounds.first.x) * (1.f / 6.f);
	ImU32 col = MakeCol(mate ? cfg::esp::colors::tracker_team
	                         : cfg::esp::colors::tracker_enemy);
	d->AddCircle(head, radius, col, 15);
}

// ── bars ─────────────────────────────────────────────────────────────────────

void Esp::RenderPlayerBars(Player player, std::pair<Vec2_t, Vec2_t> bounds) {
	// Health bar (left side, vertical)
	if (cfg::esp::health) {
		const float barL = bounds.first.x - 4.f;
		const float barR = barL - 2.f;
		const float top  = bounds.first.y;
		const float bot  = bounds.second.y;
		const float h    = bot - top;
		const float fill = h * (player.health * 0.01f);

		d->AddRectFilled(ImVec2(barL, bot - fill), ImVec2(barR, bot),
			IM_COL32(100, 255, 100, 255));
		d->AddRect(ImVec2(barL, top), ImVec2(barR, bot),
			IM_COL32(0, 0, 0, 50));

		if (cfg::esp::health_number) {
			char buf[8]; snprintf(buf, sizeof(buf), "%d", player.health);
			auto sz = font->CalcTextSizeA(cfg::esp::text_size, FLT_MAX, 0.f, buf);
			float tx = (barL + barR) * 0.5f - sz.x * 0.5f;
			float ty = bot - fill - sz.y * 0.5f;
			d->AddText(font, cfg::esp::text_size, Vec2_t(tx, ty),
				IM_COL32(255, 255, 255, 255), buf);
		}
	}

	// Armor bar (bottom, horizontal)
	if (cfg::esp::armor) {
		const float left  = bounds.first.x;
		const float right = bounds.second.x;
		const float barT  = bounds.second.y + 4.f;
		const float barB  = barT + 2.f;
		const float w     = right - left;
		const float fill  = w * (player.armor * 0.01f);

		d->AddRectFilled(ImVec2(left, barT), ImVec2(left + fill, barB),
			IM_COL32(150, 150, 255, 255));
		d->AddRect(ImVec2(left, barT), ImVec2(right, barB),
			IM_COL32(0, 0, 0, 50));
	}
}

// ── flags ─────────────────────────────────────────────────────────────────────

void Esp::RenderPlayerFalgs(Player player, std::pair<Vec2_t, Vec2_t> bounds, bool mate) {
	const float ts  = cfg::esp::text_size;
	const float step = ts + 3.f;
	const ImU32 white = IM_COL32(255, 255, 255, 255);
	const float cx = HalfX(bounds);

	// Name — centered above box
	if (cfg::esp::flags::name) {
		char nbuf[40];
		snprintf(nbuf, sizeof(nbuf), "%s%s", player.name,
			player.bot ? skCrypt(" (Bot)") : "");
		auto nsz = font->CalcTextSizeA(ts, FLT_MAX, 0.f, nbuf);
		d->AddText(font, ts,
			Vec2_t(cx - nsz.x * 0.5f, bounds.first.y - nsz.y - 4.f),
			white, nbuf);
	}

	// Weapon — centered below box
	if (cfg::esp::flags::weapon) {
		const char* wname = player.weapon.name.data();
		auto wsz = font->CalcTextSizeA(ts, FLT_MAX, 0.f, wname);
		d->AddText(font, ts,
			Vec2_t(cx - wsz.x * 0.5f, bounds.second.y + 4.f),
			white, wname);
	}

	// Ammo — below weapon
	if (cfg::esp::flags::ammo && player.ammo != -1) {
		char abuf[8]; snprintf(abuf, sizeof(abuf), "%d", player.ammo);
		auto asz = font->CalcTextSizeA(ts, FLT_MAX, 0.f, abuf);
		d->AddText(font, ts,
			Vec2_t(cx - asz.x * 0.5f, bounds.second.y + 4.f + step),
			white, abuf);
	}

	// Right-side flags (money, ping, status tags)
	int row = 0;
	if (cfg::esp::flags::money && player.money) {
		char mbuf[16]; snprintf(mbuf, sizeof(mbuf), "%d$", player.money);
		d->AddText(font, ts, RightFlagPos(bounds, row++, ts), white, mbuf);
	}
	if (cfg::esp::flags::ping) {
		char pbuf[12]; snprintf(pbuf, sizeof(pbuf), "%dms", player.ping);
		d->AddText(font, ts, RightFlagPos(bounds, row++, ts), white, pbuf);
	}
	if (cfg::esp::flags::flashed && player.flashed) {
		d->AddText(font, ts, RightFlagPos(bounds, row++, ts),
			IM_COL32(100, 255, 100, 255), skCrypt("flashed"));
	}
	if (cfg::esp::flags::defusing && player.defusing) {
		d->AddText(font, ts, RightFlagPos(bounds, row++, ts),
			IM_COL32(255, 100, 100, 255), skCrypt("defusing"));
	}
	if (cfg::esp::flags::scoped && player.scoped) {
		d->AddText(font, ts, RightFlagPos(bounds, row++, ts),
			IM_COL32(100, 100, 255, 255), skCrypt("scoped"));
	}
	if (cfg::esp::flags::reloading && player.is_reloading) {
		d->AddText(font, ts, RightFlagPos(bounds, row++, ts),
			IM_COL32(200, 200, 100, 255), skCrypt("reloading"));
	}
	(void)row;
}

// ── crosshair ─────────────────────────────────────────────────────────────────

void Esp::RenderCrosshair(Player local) {
	if (!cfg::world::crosshair::enabled || local.scoped) return;

	const float cx = floorf(io.DisplaySize.x * 0.5f);
	const float cy = floorf(io.DisplaySize.y * 0.5f);
	constexpr float kSz  = 6.f;
	constexpr float kGap = 2.f;
	constexpr float kW   = 1.5f;

	struct Arm { float x0,y0,x1,y1; };
	const Arm arms[4] = {
		{ cx-kSz, cy,    cx-kGap, cy    },
		{ cx+kGap,cy,    cx+kSz,  cy    },
		{ cx,     cy-kSz,cx,     cy-kGap},
		{ cx,     cy+kGap,cx,    cy+kSz },
	};
	for (const auto& a : arms) {
		d->AddLine({a.x0,a.y0},{a.x1,a.y1}, IM_COL32(0,0,0,160), kW+1.f);
		d->AddLine({a.x0,a.y0},{a.x1,a.y1}, IM_COL32(255,255,255,255), kW);
	}
}

// ── tracers ───────────────────────────────────────────────────────────────────

void Esp::RenderPlayerTracers(Player source, Player player, bool mate) {
	if (!cfg::esp::tracers) return;

	const float hw = io.DisplaySize.x * 0.5f;
	const float hh = io.DisplaySize.y * 0.5f;

	Vec2_t sp;
	if (!matrix.wts(player.pos, io.DisplaySize, sp, false)) {
		Vec3_t d3 = player.pos - source.pos;
		float vx = matrix[0][0]*d3.x + matrix[0][1]*d3.y + matrix[0][2]*d3.z;
		float vy = matrix[1][0]*d3.x + matrix[1][1]*d3.y + matrix[1][2]*d3.z;
		float vz = matrix[2][0]*d3.x + matrix[2][1]*d3.y + matrix[2][2]*d3.z;

		if (vz > 0.f) { vx = -vx; vy = -vy; }

		float inv = 1.f / (sqrtf(vx*vx + vy*vy) + 1e-6f);
		vx *= inv; vy *= inv;

		constexpr float kMargin = 10.f;
		sp.x = std::clamp(hw + vx * hw, kMargin, io.DisplaySize.x - kMargin);
		sp.y = std::clamp(hh - vy * hh, kMargin, io.DisplaySize.y - kMargin);
	}

	ImU32 col = MakeCol(mate ? cfg::esp::colors::tracer_team
	                         : cfg::esp::colors::tracer_enemy);
	d->AddLine(Vec2_t(hw, hh), sp, col, 1.f);
}

