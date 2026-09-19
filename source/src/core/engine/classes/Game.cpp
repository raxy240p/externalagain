#include "Game.hpp"
#include "core/debug.hpp"

#include <vector>
#include <chrono>

#include "core/engine/Engine.hpp"
#include "core/offsets/Dumper.hpp"
#include <cstring>

bool Game::Update() {
	if (!Engine::GetProcess())
		return false;

	UpdateMatrix();  // best-effort — matrix thread keeps s_viewMatrix fresh; entity reads must not be gated on this

	return true;
}

static bool IsValidViewMatrix(const view_matrix_t& vm) {
	// m[0][0] alone can be ~0 when the camera looks perpendicular to world-X.
	// Use row-0 magnitude instead: it equals P[0][0] (focal length) which is
	// rotation-invariant and always in [0.3, 3.0] for valid CS2 FOVs.
	float mag2 = vm.matrix[0][0]*vm.matrix[0][0]
	           + vm.matrix[0][1]*vm.matrix[0][1]
	           + vm.matrix[0][2]*vm.matrix[0][2];
	return mag2 > 0.1f;
}

bool Game::UpdateMatrix() {
	auto p = Engine::GetProcess();
	auto client = Engine::GetClient();
	uintptr_t vmVa = offsets::resolvedViewMatrixVA
	    ? offsets::resolvedViewMatrixVA
	    : (client.base + offsets::viewMatrix);

	view_matrix_t tryVm{};
	bool readOk = p->read_raw_cached(vmVa, &tryVm, sizeof(tryVm));
	if (readOk && IsValidViewMatrix(tryVm)) {
		this->view_matrix = tryVm;

		using clk = std::chrono::steady_clock;
		static clk::time_point s_last = clk::now() - std::chrono::seconds(10);
		if (clk::now() - s_last >= std::chrono::seconds(5)) {
			s_last = clk::now();
			DBG_PRINT("[matrix] row0: %.3f %.3f %.3f %.3f\n",
				tryVm.matrix[0][0], tryVm.matrix[0][1], tryVm.matrix[0][2], tryVm.matrix[0][3]);
			DBG_PRINT("[matrix] row1: %.3f %.3f %.3f %.3f\n",
				tryVm.matrix[1][0], tryVm.matrix[1][1], tryVm.matrix[1][2], tryVm.matrix[1][3]);
			DBG_PRINT("[matrix] row2: %.3f %.3f %.3f %.3f\n",
				tryVm.matrix[2][0], tryVm.matrix[2][1], tryVm.matrix[2][2], tryVm.matrix[2][3]);
			DBG_PRINT("[matrix] row3(W): %.3f %.3f %.3f %.3f\n",
				tryVm.matrix[3][0], tryVm.matrix[3][1], tryVm.matrix[3][2], tryVm.matrix[3][3]);
		}
		return true;
	}

	if (readOk)
		p->InvalidatePaCacheRange(vmVa, sizeof(tryVm));

	using clk = std::chrono::steady_clock;
	static clk::time_point s_last = clk::now() - std::chrono::seconds(4);
	if (clk::now() - s_last >= std::chrono::seconds(5)) {
		s_last = clk::now();
		DBG_PRINT("[SysMonitor] view matrix not ready  readOk=%d  [0][0]=%.3f [3][3]=%.3f  vmVa=0x%llX\n",
			readOk, tryVm.matrix[0][0], tryVm.matrix[3][3], (unsigned long long)vmVa);
	}
	return false;
}

bool Game::UpdateEntityList() {
	auto p = Engine::GetProcess();
	auto client = Engine::GetClient();

	constexpr uint64_t kUserLo = 0x00010000ULL;
	constexpr uint64_t kUserHi = 0x800000000000ULL;

	auto applyEntityList = [&](uint64_t el) {
		static bool s_firstEl = false;
		if (!s_firstEl) {
			s_firstEl = true;
			DBG_PRINT("[SysMonitor] entity list OK\n");
		}
		this->entity_list = el;
		m_cachedEntityListVa = el;  // cache so Path 1 handles all subsequent frames
		uint64_t le = 0;
		p->read_raw_cached(el + 0x10, &le, sizeof(le));
		this->list_entry = (le >= kUserLo && le < kUserHi) ? le : 0;
	};

	// elVa declared early so Path 1 can invalidate it on failure
	uint64_t elVa = client.base + offsets::entityList;

	// Path 1: cached entity system VA — 1 IOCTL (PhysRead only, PA is cached)
	if (m_cachedEntityListVa) {
		// Force a fresh page-walk of the chunk[0] pointer every ~3 s so a stale
		// but range-valid old pointer (e.g. after mp_restartgame) doesn't persist.
		{
			using clk = std::chrono::steady_clock;
			static clk::time_point s_lastForce = clk::now();
			if (clk::now() - s_lastForce >= std::chrono::seconds(3)) {
				s_lastForce = clk::now();
				p->InvalidatePaCacheRange(m_cachedEntityListVa, 0x20);
			}
		}
		uint64_t le = 0;
		p->read_raw_cached(m_cachedEntityListVa + 0x10, &le, sizeof(le));
		if (le >= kUserLo && le < kUserHi) {
			this->entity_list = m_cachedEntityListVa;
			this->list_entry  = le;
			return true;
		}
		// PA went stale. Flush the entity-system page AND the pointer page in
		// client.dll so Path 2 below does a fresh 4-level walk instead of
		// hitting the same dead cache entry.
		p->InvalidatePaCacheRange(m_cachedEntityListVa, 0x20);
		p->InvalidatePaCacheRange(elVa, 8);
		{
			using clk = std::chrono::steady_clock;
			static clk::time_point s_last{};
			if (clk::now() - s_last >= std::chrono::seconds(3)) {
				s_last = clk::now();
				DBG_PRINT("[Game] entity list PA stale (le=0x%llX) — re-resolving\n", (unsigned long long)le);
			}
		}
		m_cachedEntityListVa = 0;
	}

	// Path 2: hardcoded offset — PA cache was just invalidated above on first miss,
	// so this read will do a fresh page walk and re-cache the correct physical address.
	uint64_t el = 0;
	p->read_raw_cached(elVa, &el, sizeof(el));
	{
		static int s_elFailPrint = 0;
		using clk = std::chrono::steady_clock;
		static clk::time_point s_elLast = clk::now() - std::chrono::seconds(4);
		bool shouldPrint = (s_elFailPrint < 3) ||
		                   (clk::now() - s_elLast >= std::chrono::seconds(10));
		if (shouldPrint && !(el >= kUserLo && el < kUserHi)) {
			s_elLast = clk::now();
			s_elFailPrint++;
			DBG_PRINT("[SysMonitor] entity list not ready\n");
		}
	}
	if (el >= kUserLo && el < kUserHi) { applyEntityList(el); return true; }
	// Path 2 also bad — flush its PA so next cycle does a fresh walk
	p->InvalidatePaCacheRange(elVa, 8);

	// Path 3: pattern scan sweep
	static uint64_t s_resolvedElVa = 0;
	if (s_resolvedElVa) {
		el = p->read<uint64_t>(s_resolvedElVa);
		if (el >= kUserLo && el < kUserHi) { applyEntityList(el); return true; }
	}

	static bool s_searched = false;
	if (!s_searched) {
		uint64_t sweepSize = (client.size > 0x3000000) ? client.size : 0x3000000ULL;
		constexpr size_t kChunk = 0x1000;
		std::vector<uint8_t> buf(kChunk);
		int candidates = 0;
		int pagesRead  = 0, pagesFail = 0;

		for (uint64_t off = 0; off < sweepSize; off += kChunk) {
			size_t toRead = (sweepSize - off < kChunk) ? (size_t)(sweepSize - off) : kChunk;
			if (!p->read_raw(client.base + off, buf.data(), toRead)) { pagesFail++; continue; }
			pagesRead++;

			for (size_t i = 0; i + 8 <= toRead; i += 8) {
				uint64_t cand = *(uint64_t*)(buf.data() + i);
				if (cand < 0x100000000ULL || cand >= 0x7FF000000000ULL) continue;
				candidates++;

				uint64_t chunkArr = p->read<uint64_t>(cand + 0x10);
				if (chunkArr < 0x100000000ULL || chunkArr >= 0x7FF000000000ULL) continue;

				uint64_t chunk0 = p->read<uint64_t>(chunkArr);
				if (chunk0 < 0x100000000ULL || chunk0 >= 0x7FF000000000ULL) continue;

				bool slotOk = false;
				for (int s = 0; s < 4 && !slotOk; s++) {
					uint64_t slot = p->read<uint64_t>(chunk0 + (uint64_t)s * 0x70);
					if (slot >= 0x100000000ULL && slot < 0x800000000000ULL) slotOk = true;
				}
				if (!slotOk) continue;

				s_resolvedElVa = client.base + off + i;
				applyEntityList(cand);
				s_searched = true;
				return true;
			}
		}
		// Sweep completed without finding a valid candidate — leave s_searched=false
		// so the next time both Path 1 and Path 2 fail (e.g. after a map change)
		// the sweep runs again rather than giving up permanently.
	}

	{
		using clk = std::chrono::steady_clock;
		static clk::time_point s_last{};
		if (clk::now() - s_last >= std::chrono::seconds(3)) {
			s_last = clk::now();
			DBG_PRINT("[Game] entity list LOST — all paths failed\n");
		}
	}
	this->entity_list = 0;
	this->list_entry  = 0;
	return true;
}
