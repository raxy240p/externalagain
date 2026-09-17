#include "common.hpp"
#include "Weapon.hpp"
#include "core/engine/Engine.hpp"
#include "core/offsets/Dumper.hpp"
#include <skCrypter/skCrypter.hpp>

bool Weapon::Update() {
	auto p = Engine::GetProcess();
    auto client = Engine::GetClient();
	if (!p)
		return false;

    if (!entity_list)
        return false;

    uint64_t bucketOff = 0x10 + 0x8 * ((slot_index & 0x7FFF) >> 9);
    uintptr_t bucket_ptr = 0;
    p->read_raw_cached(entity_list + bucketOff, &bucket_ptr, 8);
    if (!bucket_ptr)
        return false;

    uintptr_t weapon_ptr = 0;
    p->read_raw_cached(bucket_ptr + 0x70 * (slot_index & 0x1FF), &weapon_ptr, 8);
	if (!weapon_ptr)
		return false;

	short item_idx = 0;
	p->read_raw_cached(weapon_ptr + offsets::pawn::m_AttributeManager + offsets::pawn::m_Item + offsets::pawn::m_iItemDefinitionIndex, &item_idx, 2);
	this->item_index = item_idx;

	if (!this->item_index)
		return false;

    this->name = ToString();
    int32_t ammo_val = 0;
    p->read_raw_cached(weapon_ptr + offsets::pawn::m_iClip1, &ammo_val, 4);
    this->ammo = ammo_val;
    bool reloading = false;
    p->read_raw_cached(weapon_ptr + offsets::pawn::m_bInReload, &reloading, 1);
    this->is_reloading = reloading;

	return true;
}

std::string Weapon::ToString() const
{
#define WN(s) std::string((const char*)skCrypt(s))
    switch (this->item_index)
    {
    case weapon_deagle:              return WN("Deagle");
    case weapon_elite:               return WN("Dual Berettas");
    case weapon_fiveseven:           return WN("Five-Seven");
    case weapon_glock:               return WN("Glock-18");
    case weapon_ak47:                return WN("AK-47");
    case weapon_aug:                 return WN("AUG");
    case weapon_awp:                 return WN("AWP");
    case weapon_famas:               return WN("FAMAS");
    case weapon_g3sg1:               return WN("G3SG1");
    case weapon_galilar:             return WN("Galil AR");
    case weapon_m249:                return WN("M249");
    case weapon_m4a1:                return WN("M4A1");
    case weapon_mac10:               return WN("MAC-10");
    case weapon_p90:                 return WN("P90");
    case weapon_zone_repulsor:       return WN("zone_repulsor");
    case weapon_mp5sd:               return WN("MP5-SD");
    case weapon_ump45:               return WN("UMP-45");
    case weapon_xm1014:              return WN("XM1014");
    case weapon_bizon:               return WN("PP-Bizon");
    case weapon_mag7:                return WN("MAG-7");
    case weapon_negev:               return WN("Negev");
    case weapon_sawedoff:            return WN("Sawed-Off");
    case weapon_tec9:                return WN("Tec-9");
    case weapon_taser:               return WN("Zeus x27");
    case weapon_hkp2000:             return WN("P2000");
    case weapon_mp7:                 return WN("MP7");
    case weapon_mp9:                 return WN("MP9");
    case weapon_nova:                return WN("Nova");
    case weapon_p250:                return WN("P250");
    case weapon_shield:              return WN("shield");
    case weapon_scar20:              return WN("SCAR-20");
    case weapon_sg556:               return WN("SG 556");
    case weapon_ssg08:               return WN("SSG 08");
    case weapon_knifegg:             return WN("knifegg");
    case weapon_knife:               return WN("Knife");
    case weapon_flashbang:           return WN("Flashbang");
    case weapon_hegrenade:           return WN("HE Grenade");
    case weapon_smokegrenade:        return WN("Smoke Grenade");
    case weapon_molotov:             return WN("Molotov");
    case weapon_decoy:               return WN("Decoy");
    case weapon_incgrenade:          return WN("Incendiary Grenade");
    case weapon_c4:                  return WN("C4");
    case item_kevlar:                return WN("Kevlar");
    case item_assaultsuit:           return WN("assaultsuit");
    case item_heavyassaultsuit:      return WN("heavyassaultsuit");
    case item_nvg:                   return WN("nvg");
    case item_defuser:               return WN("Defuser");
    case item_cutters:               return WN("cutters");
    case weapon_healthshot:          return WN("Healthshot");
    case weapon_knife_t:             return WN("Knife");
    case weapon_m4a1_silencer:       return WN("M4A1-S");
    case weapon_usp_silencer:        return WN("USP-S");
    case weapon_cz75a:               return WN("CZ75A");
    case weapon_revolver:            return WN("Revolver");
    case weapon_tagrenade:           return WN("tagrenade");
    case weapon_fists:               return WN("Fists");
    case weapon_breachcharge:        return WN("breachcharge");
    case weapon_tablet:              return WN("tablet");
    case weapon_melee:               return WN("melee");
    case weapon_axe:                 return WN("axe");
    case weapon_hammer:              return WN("hammer");
    case weapon_spanner:             return WN("spanner");
    case weapon_knife_ghost:         return WN("knife_ghost");
    case weapon_firebomb:            return WN("firebomb");
    case weapon_diversion:           return WN("diversion");
    case weapon_frag_grenade:        return WN("frag_grenade");
    case weapon_snowball:            return WN("snowball");
    case weapon_bumpmine:            return WN("bumpmine");
    case weapon_knife_bayonet:       return WN("Bayonet");
    case weapon_knife_css:           return WN("Classic Knife");
    case weapon_knife_flip:          return WN("Flip Knife");
    case weapon_knife_gut:           return WN("Gut Knife");
    case weapon_knife_karambit:      return WN("Karambit");
    case weapon_knife_m9_bayonet:    return WN("M9 Bayonet");
    case weapon_knife_tactical:      return WN("Huntsman Knife");
    case weapon_knife_falchion:      return WN("Falchion Knife");
    case weapon_knife_survival_bowie:return WN("Bowie Knife");
    case weapon_knife_butterfly:     return WN("Butterfly Knife");
    case weapon_knife_push:          return WN("Shadow Daggers");
    case weapon_knife_cord:          return WN("Paracord Knife");
    case weapon_knife_canis:         return WN("Survival Knife");
    case weapon_knife_ursus:         return WN("Ursus Knife");
    case weapon_knife_gypsy_jackknife:return WN("Navaja Knife");
    case weapon_knife_outdoor:       return WN("Nomad Knife");
    case weapon_knife_stiletto:      return WN("Stiletto Knife");
    case weapon_knife_widowmaker:    return WN("Widowmaker Knife");
    case weapon_knife_skeleton:      return WN("Skeleton Knife");
    case weapon_knife_kukri:         return WN("Kukri Knife");
    default:                         return WN("unknown");
    }
#undef WN
}