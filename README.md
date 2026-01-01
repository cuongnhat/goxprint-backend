# GoXPrint Driver Manager

Admin panel để quản lý printer drivers trên Cloudflare R2.

## 🏗️ Kiến trúc

```
┌─────────────────────────────────────────────────────────────┐
│                    GoXPrint Ecosystem                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────┐         ┌─────────────────────────┐    │
│  │ GoXPrint Tool   │ ──API──▶│ Cloudflare Worker API   │    │
│  │ (Desktop App)   │         │ download.goxprint.com   │    │
│  └─────────────────┘         └───────────┬─────────────┘    │
│                                          │                   │
│  ┌─────────────────┐                     │                   │
│  │ Driver Manager  │ ──────────────────────                  │
│  │ (Admin Website) │                     │                   │
│  └─────────────────┘                     ▼                   │
│                              ┌─────────────────────────┐    │
│                              │   Cloudflare R2 Bucket  │    │
│                              │   goxprint-drivers      │    │
│                              │   Public: download.     │    │
│                              │   goxprint.com          │    │
│                              └─────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## 🔧 Cấu hình R2

### Thông tin R2 Bucket:
- **Public URL:** `https://download.goxprint.com/`
- **S3 Endpoint:** `https://550d98d834457ea241cf4d14c126be97.r2.cloudflarestorage.com`
- **Bucket Name:** `goxprint-drivers`

### Cấu trúc lưu trữ:
```
goxprint-drivers/
├── drivers/           # Driver files (.zip)
│   ├── {id}_hp_universal.zip
│   ├── {id}_canon_generic.zip
│   └── ...
└── meta/              # Metadata JSON files
    ├── {id}.json
    └── ...
```

## 📦 Cài đặt

```bash
# Install dependencies
npm install

# Chạy dev server (React Admin)
npm run dev

# Chạy Worker API locally
npm run dev:worker
```

## 🚀 Deploy lên Cloudflare

### 1. Tạo R2 Bucket (nếu chưa có)
```bash
wrangler r2 bucket create goxprint-drivers
```

### 2. Cấu hình Public Access cho R2
Trong Cloudflare Dashboard:
1. Vào R2 > goxprint-drivers
2. Settings > Public access
3. Connect a custom domain: `download.goxprint.com`

### 3. Deploy Worker API
```bash
# Login Cloudflare
wrangler login

# Deploy
npm run deploy:worker
```

### 4. Deploy Admin Website (Cloudflare Pages)
1. Push code lên GitHub
2. Connect repo với Cloudflare Pages
3. Build command: `npm run build`
4. Output directory: `dist`

## 🔧 API Endpoints

Base URL: `https://download.goxprint.com/api`

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/drivers` | List all drivers |
| POST | `/api/drivers` | Upload new driver |
| GET | `/api/drivers/:id` | Get driver info |
| GET | `/api/drivers/:id/download` | Download driver file |
| DELETE | `/api/drivers/:id` | Delete driver |
| GET | `/api/health` | Health check |

## 📝 Ví dụ sử dụng API

### List drivers:
```bash
curl https://download.goxprint.com/api/drivers
```

### Upload driver:
```bash
curl -X POST https://download.goxprint.com/api/drivers \
  -F "file=@driver.zip" \
  -F "name=HP LaserJet Universal" \
  -F "manufacturer=HP" \
  -F "model=Universal" \
  -F "version=7.0"
```

### Download driver:
```bash
curl -L https://download.goxprint.com/api/drivers/{id}/download -o driver.zip
```

## 🔗 Tích hợp với GoXPrint Tool

GoXPrint Tool (app.go) đã được cấu hình để gọi API:

```go
// Default API URL
apiURL = "https://download.goxprint.com/api/drivers"
```

Khi user nhấn "Tải Driver từ Cloud" trong tab Máy in:
1. App gọi API `/api/drivers` để lấy danh sách
2. User chọn driver cần cài
3. App tải driver từ `downloadUrl` (R2 public URL)
4. App cài đặt driver tự động

## 🔒 Security (Optional)

Để bảo vệ API upload/delete, thêm authentication:

```bash
# Set API key
wrangler secret put API_KEY
```

Trong Worker, validate API key:
```typescript
const apiKey = request.headers.get('X-API-Key');
if (apiKey !== env.API_KEY) {
  return errorResponse('Unauthorized', 401);
}
```

## 📱 URLs

| Service | URL |
|---------|-----|
| API | https://download.goxprint.com/api |
| Driver Files | https://download.goxprint.com/drivers/{file} |
| Admin Panel | https://admin.goxprint.com (Cloudflare Pages) |
