"""
Случайные CDN-образные пути для маскировки VPN-трафика.

Генерирует URL-пути, имитирующие запросы к статическим ресурсам
(CSS, JS, изображения, шрифты, API, HLS и т.д.).
"""

import random


def random_cdn_path(poll_path: str) -> str:
    """Генерирует случайный CDN-путь поверх poll_path.

    Примеры:
        random_cdn_path("/poll") -> "/poll/assets/main.a1b2c3.js"
        random_cdn_path("/poll") -> "/poll/images/12345.jpg"
    """
    r = random
    dig = lambda n: ''.join(r.choice('0123456789abcdef') for _ in range(n))
    nid = lambda: str(r.randint(100, 99999999))
    base = poll_path.rstrip("/")

    pick = r.random()
    if pick < 0.18:
        ext = r.choice(['js', 'css'])
        nm = r.choice(['app', 'main', 'vendor', 'runtime', 'index', 'chunk'])
        p = f"/assets/{nm}.{dig(6)}.{ext}"
    elif pick < 0.30:
        p = f"/assets/{r.choice(['app', 'main', 'index', 'styles', 'vendor', 'bundle'])}.{r.choice(['js', 'css'])}"
    elif pick < 0.42:
        p = r.choice([
            f"/images/{nid()}.{r.choice(['jpg', 'webp', 'avif', 'png'])}",
            f"/img/{r.choice(['logo', 'banner', 'hero'])}.{r.choice(['png', 'webp'])}",
            f"/cdn/images/{nid()}.jpg",
            f"/media/{nid()}/thumbnail.jpg",
        ])
    elif pick < 0.52:
        p = r.choice([
            "/config.json", "/manifest.json", "/api/config",
            f"/locales/{r.choice(['en', 'de', 'fr', 'ru', 'es', 'it'])}.json",
            "/assets/config.json", "/assets/i18n/en-US.json",
        ])
    elif pick < 0.62:
        p = r.choice([
            f"/hls/{nid()}/master.m3u8",
            f"/hls/{nid()}/720p/index.m3u8",
            f"/video/{nid()}/seg-{r.randint(1, 99):03d}.ts",
            f"/videos/{nid()}.{r.choice(['mp4', 'mkv'])}",
        ])
    elif pick < 0.72:
        p = r.choice([
            "/_next/static/chunks/main.js",
            "/_next/static/chunks/webpack.js",
            "/_next/static/css/app.css",
            f"/assets/chunk-{r.choice(['settings', 'dashboard', 'editor', 'chat', 'login', 'profile'])}.js",
            "/_nuxt/app.js",
        ])
    elif pick < 0.80:
        p = r.choice([
            f"/download/{nid()}.zip",
            f"/objects/{nid()}/data",
            f"/uploads/{r.randint(2020, 2026)}/{r.randint(1, 12):02d}/{dig(8)}.{r.choice(['jpg', 'png'])}",
            f"/packages/{r.choice(['app', 'utils', 'core', 'tools'])}.tar.gz",
            f"/releases/v{r.randint(1, 9)}.{r.randint(0, 9)}.{r.randint(0, 9)}/app.zip",
        ])
    elif pick < 0.90:
        fam = r.choice(['inter', 'roboto', 'montserrat', 'lato', 'source-sans'])
        style = r.choice(['', 'bold-', 'regular-', 'medium-', 'semi-bold-'])
        p = f"/assets/fonts/{fam}-{style}{r.choice(['v1', 'v2', 'v3'])}.{r.choice(['woff2', 'woff', 'ttf'])}"
    else:
        p = r.choice([
            f"/api/users", f"/api/v{r.randint(1, 3)}/status",
            f"/content/{nid()}", f"/articles/{nid()}",
            f"/edge/config", f"/cdn/health",
        ])

    if r.random() < 0.35:
        p += r.choice([
            "?v=" + str(r.randint(1, 4)),
            "?v=" + str(r.randint(20260800, 20260899)),
            "?_=" + str(r.randint(1700000000, 1800000000)),
            "?cache=" + dig(6),
            "?version=" + str(r.randint(100, 999)),
        ])
    return base + p
