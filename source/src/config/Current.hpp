#pragma once

namespace cfg {
	inline bool enabled = true;

	namespace esp {
		inline bool team = true;

		inline bool box = true;
		inline bool armor = true;
		inline bool health = true;
		inline bool skeleton = true;
		inline bool head_tracker = true;
		inline bool health_number = false;

		inline bool spotted = false;

		inline float box_thickness      = 2.f;
		inline float skeleton_thickness = 1.5f;
		inline float text_size          = 9.5f;

		inline bool spotted_color = false;

		inline bool tracers = false;

		namespace flags {
			inline bool name = true;
			inline bool ping = true;
			inline bool weapon = false;
			inline bool ammo = false;
			inline bool reloading = false;
			inline bool defusing = false;
			inline bool money = false;
			inline bool flashed = false;
			inline bool scoped = false;
		}

		// Triggerbot: fires MOUSE1 (SendInput INPUT_MOUSE, LEFTDOWN+LEFTUP)
		// when the crosshair (screen center) is within hit_radius_px of any
		// bone in the selected zone on an alive enemy. Only active while
		// the bound key is held. delay_ms is the minimum interval between
		// consecutive shots on the SAME target — protects against fully-
		// auto weapon walk-on and prevents infinite fire when the crosshair
		// parks on a body.
		namespace trigger {
			inline bool  enabled       = false;
			inline int   key           = ImGuiKey_MouseX1;   // side-mouse button by default
			inline int   zone          = 0;                  // 0 = head, 1 = body, 2 = legs, 3 = any
			inline float hit_radius_px = 4.0f;               // 1..24 px around screen center
			inline int   delay_ms      = 90;                 // 20..500 ms between shots
			inline bool  ignore_flashed = true;              // don't fire while we're blinded
			inline bool  ignore_smoked  = false;             // reserved (post-processing needed)
		}

	namespace colors {
			inline color_t box_team{ 0.f, 1.f, 0.29f, 0.5f };
			inline color_t box_enemy{ 1.f, 0.f, 0.f, 0.5f };

			inline color_t skeleton_team{ 0.f, 1.f, 0.f, 0.5f };
			inline color_t skeleton_enemy{ 1.f, 0.f, 0.f, 0.5f };

			inline color_t tracker_team{ 1.f, 1.f, 1.f, 0.3f };
			inline color_t tracker_enemy{ 1.f, 1.f, 1.f, 0.3f };

			inline color_t box_spotted{ 1.f, 0.55f, 0.f, 0.9f };

			inline color_t tracer_team{ 0.f, 1.f, 0.f, 0.5f };
			inline color_t tracer_enemy{ 1.f, 0.f, 0.f, 0.5f };
		}

	}

	namespace world {
		namespace spectators {
			inline bool enabled = false;

			inline bool detailed = false;
			inline bool self_only = true;

			inline Vec2_t pos{ 10.f, 100.f };
		}

		namespace crosshair {
			inline bool enabled = false;
		}

		namespace velocity {
			inline bool enabled = false;
			inline int sample_rate = 35;
			inline float sample_length = 5.f;

			inline Vec2_t size{ 400.f, 100.f };
			inline Vec2_t pos{ 10.f, 400.f };
		}
	}

	namespace settings {
		inline bool watermark = true;
		inline bool streamproof = false;
		inline bool vsync = false;
		inline bool free_cpu = true;
		inline int  menu_key = ImGuiKey_Insert;
	}

	// UI theme — persisted via Config.cpp. Menu.cpp keeps its own runtime
	// g_accentF ImVec4 for render-hot paths; it syncs to/from cfg::ui::accent
	// on Load and Save so both stay in step across sessions.
	namespace ui {
		inline color_t accent{ 0.259f, 0.529f, 1.f, 1.f };
	}

#ifdef _DEBUG
	// Not stored, just for testing
	namespace dev {
		inline bool console = true;
		inline int open_menu_key = false;
		inline int cache_refresh_rate = 5;
	}
#endif
}