#include "Bomb.hpp"

#include "core/engine/Engine.hpp"
#include "core/offsets/Dumper.hpp"

bool Bomb::Update() {

	auto p = Engine::GetProcess();

	if (!p)
		return false;

	auto client = Engine::GetClient();

	uintptr_t is_planted = 0;
	p->read_raw_cached(client.base + offsets::plantedC4 - offsets::bomb::m_isPlanted,
	                   &is_planted, sizeof(is_planted));
	this->is_planted = is_planted;

	if (!this->is_planted) {
		Bomb::prev_is_planted = false;
		return true;
	}

	uintptr_t bomb_ptr = 0;
	p->read_raw_cached(client.base + offsets::plantedC4, &bomb_ptr, sizeof(bomb_ptr));
	if (!bomb_ptr) return false;

	uintptr_t bomb_obj = 0;
	p->read_raw_cached(bomb_ptr, &bomb_obj, sizeof(bomb_obj));
	if (!bomb_obj) return false;
	this->address = bomb_obj;

	uint32_t site = 0;
	p->read_raw_cached(bomb_obj + offsets::bomb::m_nBombSite, &site, sizeof(site));
	this->site = (site == 1) ? BombSite::B : BombSite::A;

	uintptr_t node = 0;
	p->read_raw_cached(bomb_obj + offsets::pawn::m_pGameSceneNode, &node, sizeof(node));
	if (node)
		p->read_raw_cached(node + offsets::bomb::m_vecAbsOrigin, &this->pos, sizeof(this->pos));

	bool activated = false;
	p->read_raw_cached(bomb_obj + offsets::bomb::m_bC4Activated, &activated, sizeof(activated));
	if (activated) {
		this->is_planted = false;
		this->time_left  = 0.f;
		Bomb::prev_is_planted = false;
		return true;
	}

	if (!Bomb::prev_is_planted)
		plant_time = std::time(nullptr);

	this->time_left = std::max(0.f, 41.f - (float)(std::time(nullptr) - plant_time));

	Bomb::prev_is_planted = true;
	return true;
}

std::time_t Bomb::plant_time{};
bool Bomb::prev_is_planted = false;