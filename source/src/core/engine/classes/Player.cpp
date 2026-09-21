#include "Player.hpp"
#include "core/debug.hpp"

#include <chrono>
using steady_clock = std::chrono::steady_clock;
#include <cstdio>
#include <cstdarg>

// FLog was a per-frame diagnostic writer to a hardcoded desktop path.
// Both the path string ("C:\\Users\\...\\esp_debug.txt") and the "FLog"
// call sites are trivial IOCs for static signature scanners. Neutered
// to an empty inline no-op so the compiler drops the calls entirely
// and no diagnostic strings leak into the binary.
static inline void FLog(const char*, ...) {}
#include "Weapon.hpp"
#include "core/engine/Engine.hpp"
#include "core/engine/DebugEsp.hpp"
#include "core/offsets/Dumper.hpp"

#include "core/engine/classes/ObserverServices.hpp"

bool Player::Update() {
	if (!Engine::GetProcess())
		return false;

	if (!GetController())
		return false;

	if (!GetPawn())
		return false;

	if (!UpdateController())
		return false;

	if (!UpdatePawn()) {
		static steady_clock::time_point s_last[64]{};
		auto _now = steady_clock::now();
		int si_ = (index >= 0 && index < 64) ? index : 0;
		if (_now - s_last[si_] >= std::chrono::seconds(3)) {
			s_last[si_] = _now;
			DBG_PRINT("[P%d] UpdatePawn fail pawn=0x%llX\n", index, (unsigned long long)pawn);
		}
		return false;
	}

	return true;
}

bool Player::GetController() {
	auto p = Engine::GetProcess();

	// list_entry IS chunk[0]. Controllers are at (index + 1) * 0x70 to skip
	// slot 0 (the world/game-manager entity). This mirrors the original
	// working code's iteration pattern.
	uint64_t ctrl = 0;
	p->read_raw_cached(list_entry + (uint64_t)(index + 1) * 0x70, &ctrl, 8);

	// Accept any non-null user-mode address (ASLR layout varies by build).
	constexpr uint64_t kLo = 0x10000ULL;
	constexpr uint64_t kHi = 0x800000000000ULL;
	if (!ctrl || ctrl < kLo || ctrl >= kHi) {
		p->InvalidatePaCacheRange(list_entry + (uint64_t)(index + 1) * 0x70, 8);
		return false;
	}

	this->controller = ctrl;
	return true;
}

bool Player::GetPawn() {
	auto p = Engine::GetProcess();

	uint32_t pawn_handle = 0;
	p->read_raw_cached(controller + offsets::controller::m_hPlayerPawn, &pawn_handle, 4);

	if (!pawn_handle) {
		static steady_clock::time_point s_last[64]{};
		auto _now = steady_clock::now();
		int si_ = (index >= 0 && index < 64) ? index : 0;
		if (_now - s_last[si_] >= std::chrono::seconds(3)) {
			s_last[si_] = _now;
			DBG_PRINT("[P%d] stale ctrl PA (handle=0) ctrl=0x%llX\n", index, (unsigned long long)controller);
		}
		p->InvalidatePaCacheRange(controller, 0x840);
		return false;
	}
	// Valthrun: entity index lives in the low 15 bits of the handle; valid slots have index < 0x7FF0.
	// 0xFFFFFFFF gives index 0x7FFF (>= 0x7FF0) — legitimate "no pawn" for observer/spectator slots.
	// Any other garbage read with high index bits is silently discarded here too.
	if ((pawn_handle & 0x7FFF) >= 0x7FF0)
		return false;

	this->pawn_controller_addr = pawn_handle;

	uint64_t bucketOff = 0x10 + (uint64_t)((pawn_handle & 0x7FFF) >> 9) * 8;
	uintptr_t pawn_list_entry = 0;
	p->read_raw_cached(entity_list + bucketOff, &pawn_list_entry, 8);
	constexpr uint64_t kLo = 0x10000ULL;
	constexpr uint64_t kHi = 0x800000000000ULL;

	uint32_t slot = pawn_handle & 0x1FF;
	uint64_t pawnVal = 0;
	if (pawn_list_entry >= kLo && pawn_list_entry < kHi) {
		p->read_raw_cached(pawn_list_entry + (uint64_t)slot * 0x70, &pawnVal, 8);
	}

	static int s_gpLog = 0;
	if (s_gpLog < 4) {
		s_gpLog++;
		printf("[GP] idx=%d ctrl=0x%llX handle=0x%X bucket=%llu slot=%u ple=0x%llX pawn=0x%llX\n",
		       index, (unsigned long long)controller, pawn_handle,
		       (unsigned long long)((pawn_handle & 0x7FFF) >> 9), slot,
		       (unsigned long long)pawn_list_entry, (unsigned long long)pawnVal);
	}

	if (pawnVal >= kLo && pawnVal < kHi) {
		this->pawn = pawnVal;
		return true;
	}
	// pawnVal out of range: the entity list bucket or pawn slot PA is stale.
	// Flush both so the next frame re-walks and gets the correct physical address.
	p->InvalidatePaCacheRange(entity_list + bucketOff, 8);
	if (pawn_list_entry >= kLo && pawn_list_entry < kHi)
		p->InvalidatePaCacheRange(pawn_list_entry + (uint64_t)slot * 0x70, 8);
	return false;
}

bool Player::UpdateController() {
	auto p = Engine::GetProcess();

	uint8_t cbuf[0x840] = {};
	if (!p->read_raw_cached(controller, cbuf, sizeof(cbuf))) {
		p->InvalidatePaCacheRange(controller, sizeof(cbuf));
		return false;
	}

	this->steam_id = *(uint64_t*)(cbuf + offsets::controller::m_steamID);
	this->bot = (this->steam_id == 0);

	memcpy(this->name, cbuf + offsets::controller::m_iszPlayerName, sizeof(this->name) - 1);
	this->name[sizeof(this->name) - 1] = '\0';

	this->localplayer = *(bool*)(cbuf + offsets::controller::m_bIsLocalPlayerController);
	this->ping        = *(int*)(cbuf + offsets::controller::m_iPing);

	uint64_t money_services = *(uint64_t*)(cbuf + offsets::controller::m_pInGameMoneyServices);
	if (money_services >= 0x10000000000ULL && money_services < 0x800000000000ULL) {
		int acc = 0;
		p->read_raw_cached(money_services + offsets::controller::m_iAccount, &acc, 4);
		this->money = acc;
	}

	return true;
}

bool Player::UpdatePawn() {
	auto p = Engine::GetProcess();

	if (pawn < 0x10000000000ULL || pawn >= 0x800000000000ULL) {
		this->health = 0;
		this->alive  = false;
		return false;
	}

	// read_raw_partial stops at the first unreadable physical page and returns
	// bytes successfully read. We need at least 0x400 bytes for health/team/vel/
	// sceneNode — all within the first ~0x800 bytes (page 1 for any pawn alignment).
	uint8_t pbuf[0x1D00] = {};
	size_t got = p->read_raw_partial(pawn, pbuf, sizeof(pbuf));
	if (got < 0x400) {
		p->InvalidatePaCacheRange(pawn, sizeof(pbuf));
		static steady_clock::time_point s_last[64]{};
		auto _now = steady_clock::now();
		int si_ = (this->index >= 0 && this->index < 64) ? (int)this->index : 0;
		if (_now - s_last[si_] >= std::chrono::seconds(3)) {
			s_last[si_] = _now;
			DBG_PRINT("[P%d] partial pawn read: got=%zu pawn=0x%llX\n", this->index, got, (unsigned long long)pawn);
		}
		this->health = 0;
		this->alive  = false;
		return false;
	}

	int rawHp = *(int*)(pbuf + offsets::pawn::m_iHealth);

	if (rawHp < -1 || rawHp > 200) {
		static steady_clock::time_point s_last[64]{};
		auto _now = steady_clock::now();
		int si_ = (this->index >= 0 && this->index < 64) ? (int)this->index : 0;
		if (_now - s_last[si_] >= std::chrono::seconds(3)) {
			s_last[si_] = _now;
			DBG_PRINT("[P%d] garbage HP=%d pawn=0x%llX — flushing PA\n",
			       this->index, rawHp, (unsigned long long)pawn);
		}
		p->InvalidatePaCacheRange(pawn, sizeof(pbuf));
		// Retry with a fresh PA walk immediately — pawn PA was stale (respawn/realloc).
		memset(pbuf, 0, sizeof(pbuf));
		got = p->read_raw_partial(pawn, pbuf, sizeof(pbuf));
		if (got < 0x400) { this->health = 0; this->alive = false; return false; }
		rawHp = *(int*)(pbuf + offsets::pawn::m_iHealth);
		if (rawHp < -1 || rawHp > 200) { this->health = 0; this->alive = false; return false; }
	}

	// m_lifeState 0 = LIFE_ALIVE; anything else means dying/dead even if health hasn't zeroed yet
	uint8_t lifeState = *(uint8_t*)(pbuf + offsets::pawn::m_lifeState);

	this->health = (rawHp < 0) ? 0 : rawHp;
	this->alive  = (rawHp > 0 && rawHp <= 100 && lifeState == 0);
	if (g_debugForceEspDraw)
		this->alive = true;

	static int s_upLog = 0;
	if (s_upLog < 8) {
		s_upLog++;
		float px_ = *(float*)(pbuf + offsets::pawn::m_vOldOrigin + 0);
		float py_ = *(float*)(pbuf + offsets::pawn::m_vOldOrigin + 4);
		float pz_ = *(float*)(pbuf + offsets::pawn::m_vOldOrigin + 8);
		printf("[UP] idx=%d hp=%d ls=%u alive=%d pos=(%.0f,%.0f,%.0f)\n",
		       index, rawHp, (unsigned)lifeState, (int)this->alive, px_, py_, pz_);
		FLog("[UP] idx=%d hp=%d ls=%u alive=%d pos=(%.0f,%.0f,%.0f)\n",
		     index, rawHp, (unsigned)lifeState, (int)this->alive, px_, py_, pz_);
	}

	// Team must be read before the alive early-return: fresh Player objects are created
	// every frame (Cache.cpp line 70), so team stays 0 when dead → local.team=0 → mate
	// is always false → team filter never fires → teammates render. m_iTeamNum is at
	// 0x3E7, always within the minimum 0x400 read, so this is always safe.
	if (got >= (size_t)(offsets::pawn::m_iTeamNum + 1))
		this->team = *(uint8_t*)(pbuf + offsets::pawn::m_iTeamNum);

	// Observer services is at 0x11F8 — only available when page 2 was readable
	if (got >= (size_t)(offsets::pawn::m_pObserverServices + 8)) {
		uint64_t obs_addr = *(uint64_t*)(pbuf + offsets::pawn::m_pObserverServices);
		if (obs_addr >= 0x10000000000ULL && obs_addr < 0x800000000000ULL) {
			this->observer_services.SetAddress(obs_addr);
			this->observer_services.Update();
		}
	}

	if (!this->alive)
		return true;

	// sceneNode is at 0x330 — always in page 1 for any reasonable pawn alignment
	uint64_t sceneNode = *(uint64_t*)(pbuf + offsets::pawn::m_pGameSceneNode);

	// Position: prefer m_vOldOrigin from pawn (updated at end of movement tick).
	// If page 2 is unreadable, fall back to CGameSceneNode::m_vecAbsOrigin (0xC8)
	// which is a separate heap allocation with its own independent physical pages.
	if (got >= (size_t)(offsets::pawn::m_vOldOrigin + 12)) {
		memcpy(&this->pos, pbuf + offsets::pawn::m_vOldOrigin, sizeof(Vec3_t));
	} else if (sceneNode >= 0x10000000000ULL && sceneNode < 0x800000000000ULL) {
		if (!p->read_raw_cached(sceneNode + 0xC8, &this->pos, sizeof(Vec3_t))) {
			this->alive = false;
			return false;
		}
	} else {
		this->alive = false;
		return false;
	}

	bool posOk = isfinite(this->pos.x) && isfinite(this->pos.y) && isfinite(this->pos.z)
	          && fabs(this->pos.x) <= 16384.0f
	          && fabs(this->pos.y) <= 16384.0f
	          && fabs(this->pos.z) <= 16384.0f;
	if (!posOk) {
		static int s_pfLog = 0;
		if (s_pfLog < 4) {
			s_pfLog++;
			printf("[PF] idx=%d pos=(%.1f,%.1f,%.1f)\n",
			       index, this->pos.x, this->pos.y, this->pos.z);
			FLog("[PF] idx=%d pos=(%.1f,%.1f,%.1f)\n",
			     index, this->pos.x, this->pos.y, this->pos.z);
		}
		p->InvalidatePaCacheRange(pawn, sizeof(pbuf));
		this->alive = false;
		return false;
	}

	// Eye angles — offset 0x3320 is beyond the primary pawn buffer; separate read.
	// QAngle layout: [pitch=x, yaw=y, roll=z]. We want y (yaw) for radar direction.
	{
		Vec3_t ang{};
		if (p->read_raw_cached(pawn + offsets::pawn::m_angEyeAngles, &ang, sizeof(ang))
		    && ang.y >= -360.f && ang.y <= 360.f)
			this->yaw = ang.y;
	}

	// Fields in page 2 — guarded; default to zero when page 2 is unreadable
	if (got >= (size_t)(offsets::pawn::m_vecAbsVelocity + 12))
		memcpy(&this->vel,       pbuf + offsets::pawn::m_vecAbsVelocity, sizeof(Vec3_t));
	if (got >= (size_t)(offsets::pawn::m_flFlashOverlayAlpha + 4))
		this->flashed = *(float*)(pbuf + offsets::pawn::m_flFlashOverlayAlpha) > 0;

	// Secondary fields in page 3 — all safely default to 0 (pbuf is zero-init)
	this->armor    = (got >= (size_t)(offsets::pawn::m_ArmorValue    + 4)) ? *(int*)  (pbuf + offsets::pawn::m_ArmorValue)    : 0;
	this->defusing = (got >= (size_t)(offsets::pawn::m_bIsDefusing   + 1)) ? *(bool*) (pbuf + offsets::pawn::m_bIsDefusing)   : false;
	if (got >= (size_t)(offsets::pawn::m_entitySpottedState + offsets::pawn::m_bSpottedByMask + 8)) {
		auto* maskPtr = (uint32_t*)(pbuf + offsets::pawn::m_entitySpottedState + offsets::pawn::m_bSpottedByMask);
		this->spotted_by_mask = (uint64_t)maskPtr[1] << 32 | maskPtr[0];
		this->spotted         = (this->spotted_by_mask != 0);
	} else {
		this->spotted_by_mask = ~0ULL;
		this->spotted         = true;
	}
	this->scoped   = (got >= (size_t)(offsets::pawn::m_bIsScoped     + 1)) ? *(bool*) (pbuf + offsets::pawn::m_bIsScoped)     : false;

	uint64_t weapon_services = (got >= (size_t)(offsets::pawn::m_pWeaponServices + 8))
	                           ? *(uint64_t*)(pbuf + offsets::pawn::m_pWeaponServices) : 0;

	bool skelOk = UpdateSkeleton(sceneNode);
	if (!skelOk || this->bone_list.empty()) {
		static steady_clock::time_point s_last[64]{};
		auto _now = steady_clock::now();
		int si_ = (this->index >= 0 && this->index < 64) ? (int)this->index : 0;
		if (_now - s_last[si_] >= std::chrono::seconds(3)) {
			s_last[si_] = _now;
			DBG_PRINT("[P%d] skeleton empty: skelOk=%d bones=%d sceneNode=0x%llX got=%zu\n",
			       this->index, (int)skelOk, (int)this->bone_list.size(),
			       (unsigned long long)sceneNode, got);
		}
	}
	UpdateWeapon(weapon_services);

	static int s_paLog = 0;
	if (s_paLog < 4) {
		s_paLog++;
		printf("[PA] idx=%d pos=(%.0f,%.0f,%.0f) team=%d bones=%zu alive=%d\n",
		       index, this->pos.x, this->pos.y, this->pos.z,
		       (int)this->team, this->bone_list.size(), (int)this->alive);
		FLog("[PA] idx=%d pos=(%.0f,%.0f,%.0f) team=%d bones=%zu alive=%d\n",
		     index, this->pos.x, this->pos.y, this->pos.z,
		     (int)this->team, this->bone_list.size(), (int)this->alive);
	}

	return true;
}

bool Player::UpdateSkeleton(uint64_t game_scene) {
	auto p = Engine::GetProcess();

	this->bone_list.assign(30, {});

	if (!game_scene || game_scene < 0x10000000000ULL || game_scene >= 0x800000000000ULL)
		return false;

	uintptr_t boneArrayPtrVA = game_scene + (offsets::bone::m_modelState + 0x80);
	uint64_t bone_array = 0;
	if (!p->read_raw_cached(boneArrayPtrVA, &bone_array, 8)
		|| !bone_array || bone_array < 0x10000000000ULL || bone_array >= 0x800000000000ULL) {
		p->InvalidatePaCacheRange(boneArrayPtrVA, 8);
		return false;
	}

	memset(bones, 0, sizeof(bones));
	bool boneReadOk = p->read_raw_cached(bone_array, bones, sizeof(bones));
	bool freshWalk = false;
	if (!boneReadOk) {
		p->InvalidatePaCacheRange(bone_array, sizeof(bones));
		if (p->read_raw_partial(bone_array, bones, sizeof(bones)) < sizeof(bones[0]))
			return false;
		freshWalk = true;
	}

	bool anyValid = false;
	for (int i = 0; i < 30; i++) {
		const Vec3_t& bp = bones[i].pos;
		if (!isfinite(bp.x) || !isfinite(bp.y) || !isfinite(bp.z)) continue;
		if (fabs(bp.x) > 16384.0f || fabs(bp.y) > 16384.0f || fabs(bp.z) > 16384.0f) continue;
		// Skip origin-distance guard on a fresh PA walk: this->pos (m_vOldOrigin)
		// may still be from the previous spawn while bones already reflect the new
		// spawn point — the delta can exceed 300 units on a round restart.
		if (!freshWalk) {
			float dx = bp.x - this->pos.x;
			float dy = bp.y - this->pos.y;
			float dz = bp.z - this->pos.z;
			if (dx*dx + dy*dy + dz*dz > 300.f * 300.f) continue;
		}
		this->bone_list[i] = { bp };
		anyValid = true;
	}

	// Cached read returned data but every bone failed the distance filter — the
	// physical page is stale (bone array reallocated to a new PA by CS2).
	// Flush now so the next frame re-walks and gets the correct positions.
	if (boneReadOk && !anyValid)
		p->InvalidatePaCacheRange(bone_array, sizeof(bones));

	return true;
}

bool Player::UpdateWeapon(uint64_t weapon_services) {
	auto p = Engine::GetProcess();

	if (!weapon_services)
		return false;

	int active_weapon_index = 0;
	p->read_raw_cached(weapon_services + offsets::pawn::m_hActiveWeapon, &active_weapon_index, 4);

	if (!active_weapon_index)
		return false;

	auto weapon = Weapon(this->entity_list, active_weapon_index);

	if (!weapon.Update())
		return false;

	this->weapon = weapon;
	this->ammo = weapon.ammo;
	this->is_reloading = weapon.is_reloading;

	return true;
}

bool Player::GetBounds(view_matrix_t matrix, Vec2_t size, std::pair<Vec2_t, Vec2_t>& bounds) {
	Vec2_t feet{}, head{};
	// check_bounds=false: get real screen coords even for off-screen points.
	// Returns false only when the point is behind the camera (view <= 0.01).
	bool pt1 = matrix.wts(this->pos, size, feet, false);

	Vec3_t pos_head;
	const auto& hb = this->bone_list[bone_index::head];
	bool headValid = (hb.pos.x != 0 || hb.pos.y != 0 || hb.pos.z != 0);
	pos_head = headValid ? hb.pos : (this->pos + Vec3_t(0, 0, 65.f));

	bool pt2 = matrix.wts(pos_head, size, head, false);

	if (!pt1 && !pt2) return false;
	// One point behind camera: extrapolate to the opposite screen edge.
	if (!pt1) feet = Vec2_t(head.x, size.y);
	if (!pt2) head = Vec2_t(feet.x, 0.f);

	float screenTopY = std::min(feet.y, head.y);
	float screenBotY = std::max(feet.y, head.y);
	float midX       = (feet.x + head.x) * 0.5f;

	float height = screenBotY - screenTopY;
	if (height < 2.f) height = 2.f;
	float width = height / 2.4f;

	Vec2_t top(midX - width * 0.5f, screenTopY - width * 0.25f);
	Vec2_t bot(midX + width * 0.5f, screenBotY);

	// Clamp to screen to prevent ImGui from drawing multi-screen-wide primitives.
	constexpr float kMargin = 2.f;
	top.x = std::clamp(top.x, -kMargin, size.x + kMargin);
	top.y = std::clamp(top.y, -kMargin, size.y + kMargin);
	bot.x = std::clamp(bot.x, -kMargin, size.x + kMargin);
	bot.y = std::clamp(bot.y, -kMargin, size.y + kMargin);

	if (bot.x - top.x < 1.f || bot.y - top.y < 1.f) return false;

	bounds = { top, bot };
	return true;
}

bool Player::UpdateObserverServices() {
	auto p = Engine::GetProcess();
	if (!p) 
		return false;

	DWORD64 address = p->read<DWORD64>(this->pawn + offsets::pawn::m_pObserverServices);
	if (!address) 
		return false;

	this->observer_services.SetAddress(address);
	return this->observer_services.Update();
}
