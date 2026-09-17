#include "Globals.hpp"

#include "core/engine/Engine.hpp"
#include "core/offsets/Dumper.hpp"

bool Globals::Update() {
	auto p = Engine::GetProcess();
	auto client = Engine::GetClient();

	if (!p)
		return false;

	uintptr_t addr = 0;
	p->read_raw_cached(client.base + offsets::globalVars, &addr, sizeof(addr));
	if (!addr) return false;
	this->address = addr;

	p->read_raw_cached(addr + offsets::global::currentTime, &this->current_time, sizeof(this->current_time));
	p->read_raw_cached(addr + offsets::global::maxClients,  &this->max_clients,  sizeof(this->max_clients));
	this->in_match = this->max_clients > 1;

	DWORD64 map_name_addr = 0;
	p->read_raw_cached(addr + offsets::global::currentMapName, &map_name_addr, sizeof(map_name_addr));
	if (!p->read_raw_cached(map_name_addr, this->map_name, sizeof(this->map_name)))
		return false;

	return true;
}

