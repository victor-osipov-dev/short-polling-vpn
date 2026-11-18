import { useMemo, useState } from "react";
import { Check, Search, SlidersHorizontal, X } from "lucide-react";
import type { Profile, VpnState } from "../types";

interface ProfilesSectionProps {
  state: VpnState;
  selectedId: string | null;
  connectedProfileId: string | null;
  busy: string | null;
  onSelect: (profile: Profile) => void;
}

type FilterId = "all" | "direct" | "via-ru" | "cdn" | "xhttp";

const FILTERS: { id: FilterId; label: string }[] = [
  { id: "all", label: "Все" },
  { id: "direct", label: "Прямые" },
  { id: "via-ru", label: "Через Россию" },
  { id: "cdn", label: "CDN" },
  { id: "xhttp", label: "xhttp" },
];

function matchFilter(profile: Profile, filter: FilterId): boolean {
  switch (filter) {
    case "all":
      return true;
    case "direct":
      return profile.chain.length <= 1;
    case "via-ru":
      return profile.tags.includes("Через Россию");
    case "cdn":
      return profile.tags.includes("CDN");
    case "xhttp":
      return profile.tags.includes("xhttp");
  }
}

export function ProfilesSection({ state, selectedId, connectedProfileId, busy, onSelect }: ProfilesSectionProps) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<FilterId>("all");

  const groups = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    const list = state.profiles.filter((profile) => {
      if (!matchFilter(profile, filter)) return false;
      if (!normalized) return true;
      return (
        profile.name.toLowerCase().includes(normalized) ||
        profile.regionName.toLowerCase().includes(normalized) ||
        profile.tags.some((tag) => tag.toLowerCase().includes(normalized))
      );
    });
    const byRegion = new Map<string, Profile[]>();
    for (const profile of list) {
      const key = profile.regionName || profile.region;
      const bucket = byRegion.get(key) || [];
      bucket.push(profile);
      byRegion.set(key, bucket);
    }
    return [...byRegion.entries()]
      .map(([region, profiles]) => ({
        region,
        flag: profiles[0].flag,
        profiles: profiles.sort((a, b) => a.sortOrder - b.sortOrder),
      }))
      .sort((a, b) => a.profiles[0].sortOrder - b.profiles[0].sortOrder);
  }, [state.profiles, query, filter]);

  const shown = groups.reduce((sum, group) => sum + group.profiles.length, 0);

  return (
    <section>
      <div className="section-head">
        <div>
          <div className="section-title">Профили</div>
          <div className="section-sub">
            Выберите выход и режим маршрутизации. При подключении профиль применяется мгновенно.
          </div>
        </div>
        <div className="filters">
          <div className="search">
            <Search size={14} />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Поиск профиля…"
              spellCheck={false}
            />
            {query && (
              <button
                onClick={() => setQuery("")}
                aria-label="Очистить поиск"
                style={{
                  position: "absolute",
                  right: 9,
                  top: "50%",
                  transform: "translateY(-50%)",
                  background: "none",
                  border: 0,
                  color: "rgba(238,241,255,.4)",
                  padding: 0,
                  display: "grid",
                }}
              >
                <X size={14} />
              </button>
            )}
          </div>
          {FILTERS.map((item) => (
            <button
              key={item.id}
              className={`filter-chip ${filter === item.id ? "active" : ""}`}
              onClick={() => setFilter(item.id)}
            >
              {item.label}
            </button>
          ))}
        </div>
      </div>

      {shown === 0 ? (
        <div className="card empty-profiles" style={{ marginTop: 14 }}>
          <SlidersHorizontal size={22} style={{ margin: "0 auto 8px", opacity: 0.5 }} />
          Ничего не найдено. Попробуйте другой запрос или фильтр.
        </div>
      ) : (
        groups.map((group) => (
          <div className="country-group" key={group.region}>
            <div className="country-head">
              <span className="country-flag">{group.flag}</span>
              <span className="country-name">{group.region}</span>
              <span className="country-count">{group.profiles.length}</span>
            </div>
            <div className="profiles-grid">
              {group.profiles.map((profile) => {
                const selected = selectedId === profile.id || connectedProfileId === profile.id;
                const isConnected = connectedProfileId === profile.id;
                return (
                  <button
                    key={profile.id}
                    className={`profile-card ${selected ? "selected" : ""}`}
                    style={{ ["--card-color" as string]: profile.color }}
                    onClick={() => onSelect(profile)}
                    disabled={busy !== null}
                    title={isConnected ? "Текущий профиль" : "Выбрать и переподключиться"}
                  >
                    <div className="profile-top">
                      <span className="profile-flag">{profile.flag}</span>
                      <span className="profile-name">{profile.name}</span>
                      {selected && (
                        <span className="profile-check">
                          <Check size={13} strokeWidth={3.2} />
                        </span>
                      )}
                    </div>
                    <div className="profile-tags">
                      {profile.tags.map((tag) => (
                        <span className="tag" key={tag}>
                          {tag}
                        </span>
                      ))}
                    </div>
                    <div className="profile-foot">
                      <span className="profile-chain">{profile.primaryLabel}</span>
                      <span className="profile-state">
                        {isConnected ? "подключено" : selected ? "выбран" : "выбрать"}
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        ))
      )}
    </section>
  );
}
