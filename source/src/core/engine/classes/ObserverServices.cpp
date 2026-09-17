#include "ObserverServices.hpp"
#include "core/engine/Engine.hpp"
#include "core/offsets/Dumper.hpp"

// XOR-encrypted strings at key=0x73 — plaintext never appears in binary
#define XOR73(c) ((c) ^ 0x73)
static const char _encAlive[]   = { XOR73('S'),XOR73('e'),XOR73('l'),XOR73('f'),0 };
static const char _encOne[]     = { XOR73('1'),0 };
static const char _encFirst[]   = { XOR73('F'),XOR73('i'),XOR73('r'),XOR73('s'),XOR73('t'),XOR73(' '),XOR73('p'),XOR73('e'),XOR73('r'),XOR73('s'),XOR73('o'),XOR73('n'),0 };
static const char _encThird[]   = { XOR73('T'),XOR73('h'),XOR73('i'),XOR73('r'),XOR73('d'),XOR73(' '),XOR73('p'),XOR73('e'),XOR73('r'),XOR73('s'),XOR73('o'),XOR73('n'),0 };
static const char _encFree[]    = { XOR73('F'),XOR73('r'),XOR73('e'),XOR73('e'),XOR73(' '),XOR73('R'),XOR73('o'),XOR73('a'),XOR73('m'),0 };
static const char _encUnknown[] = { XOR73('U'),XOR73('n'),XOR73('k'),XOR73('n'),XOR73('o'),XOR73('w'),XOR73('n'),0 };

struct ObsBuf { char buf[32]; bool done = false; };

#define OBS_DEC(idx, enc) do { \
    static ObsBuf _obs##idx; \
    if (!_obs##idx.done) { \
        for (int _i = 0; _i < 31 && enc[_i]; ++_i) \
            _obs##idx.buf[_i] = enc[_i] ^ 0x73; \
        _obs##idx.done = true; \
    } \
    return _obs##idx.buf; \
} while(0)

bool ObserverServices::Update() {
	auto p = Engine::GetProcess();

	if (!p)
		return false;

	if (!this->address) 
		return false;

	p->read_raw_cached(this->address + offsets::observerServices::m_iObserverMode,   &this->mode,   sizeof(this->mode));
	p->read_raw_cached(this->address + offsets::observerServices::m_hObserverTarget, &this->target, sizeof(this->target));

	return true;
}

void ObserverServices::SetAddress(DWORD64 address) {
	this->address = address;
}

const char* ObserverServices::ToString() const {
	switch (this->mode)
	{
	case ObserverMode::Alive:   { OBS_DEC(0, _encAlive);   }
	case ObserverMode::Unknown:   { OBS_DEC(1, _encOne);     }
	case ObserverMode::First: { OBS_DEC(2, _encFirst);   }
	case ObserverMode::Third: { OBS_DEC(3, _encThird);   }
	case ObserverMode::Free: { OBS_DEC(4, _encFree);    }
	default:      { OBS_DEC(5, _encUnknown); }
	}
}