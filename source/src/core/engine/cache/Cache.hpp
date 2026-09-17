#pragma once
#include "core/engine/classes/Game.hpp"
#include "core/engine/classes/Player.hpp"
#include "core/engine/classes/Globals.hpp"

using namespace std::chrono;

struct Snapshot {
	Game game;
	Player local;
	Globals globals;
	std::vector<Player> players;
	steady_clock::time_point captured;  // when the player scan completed
};

class Cache {
public:
	Game game;
	Player local;
	Globals globals;
	std::vector<Player> players;
public:
	static Cache& Get()
	{
		static Cache instance{};
		return instance;
	}

	static Snapshot CopySnapshot();

	static bool Refresh();
private:
	std::mutex mtx;
	milliseconds duration{1};
	steady_clock::time_point last{};
private:
	bool RefreshImpl();
};