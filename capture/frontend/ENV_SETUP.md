# Environment Variables Setup

## Cách set VITE_KIBANA_URL và VITE_KIBANA_DASHBOARD_ID

### Bước 1: Tạo file .env

Tạo file `.env` trong thư mục `capture/frontend/`:

```bash
cd capture/frontend
cp .env.example .env
```

### Bước 2: Cấu hình Kibana URL

Mở file `.env` và set:

```env
# Kibana URL (VPN IP của Capture Server)
VITE_KIBANA_URL=http://10.8.0.1:5601
```

**Lưu ý**: Nếu bạn truy cập Kibana từ client qua VPN, dùng VPN IP `10.8.0.1`.

### Bước 3: Tạo Dashboard trong Kibana và lấy Dashboard ID

1. **Truy cập Kibana**:
   ```
   http://10.8.0.1:5601
   ```

2. **Tạo Dashboard mới**:
   - Vào **Dashboard** → **Create Dashboard**
   - Thêm visualizations:
     - **Line Chart**: Traffic frequency theo thời gian
     - **Bar Chart**: Top countries
     - **Pie Chart**: Log types distribution
     - **Metric**: Total requests
   
3. **Lấy Dashboard ID**:
   - Sau khi tạo xong, URL sẽ có dạng:
     ```
     http://10.8.0.1:5601/app/kibana#/dashboard/abc123def456
     ```
   - Dashboard ID là phần sau `/dashboard/` → `abc123def456`

4. **Set Dashboard ID trong .env**:
   ```env
   VITE_KIBANA_DASHBOARD_ID=abc123def456
   ```

### Bước 4: Rebuild Frontend

Sau khi cấu hình xong, rebuild frontend:

```bash
cd capture/frontend
npm run build
```

Hoặc nếu dùng Docker:

```bash
cd capture
docker-compose build frontend
docker-compose up -d frontend
```

## Kiểm tra

1. Truy cập Dashboard page: `http://10.8.0.1:3000`
2. Scroll xuống phần "Traffic Frequency Analytics"
3. Nếu thấy Kibana dashboard embed → OK
4. Nếu thấy fallback stats → Kiểm tra lại:
   - Kibana URL đúng chưa
   - Dashboard ID đúng chưa
   - Kibana có chạy không: `curl http://10.8.0.1:5601/api/status`

## Troubleshooting

### Kibana không hiển thị

1. **Kiểm tra Kibana có chạy không**:
   ```bash
   docker ps | grep kibana
   curl http://10.8.0.1:5601/api/status
   ```

2. **Kiểm tra Dashboard ID**:
   - Vào Kibana → Dashboard → Chọn dashboard
   - Copy ID từ URL

3. **Kiểm tra CORS (nếu cần)**:
   - Thêm vào `kibana.yml`:
     ```yaml
     server.cors.enabled: true
     server.cors.allowOrigin: ["http://10.8.0.1:3000"]
     ```

### Environment variables không load

1. **Restart dev server** (nếu đang dev):
   ```bash
   npm run dev
   ```

2. **Clear cache và rebuild**:
   ```bash
   rm -rf node_modules/.vite
   npm run build
   ```

## Cấu trúc file .env

```env
# Kibana Configuration
VITE_KIBANA_URL=http://10.8.0.1:5601
VITE_KIBANA_DASHBOARD_ID=your-dashboard-id-here

# Optional: API Configuration
# VITE_API_URL=http://10.8.0.1:8082
```

**Lưu ý**: 
- Tất cả biến môi trường trong Vite phải bắt đầu bằng `VITE_`
- File `.env` không nên commit vào git (đã có trong `.gitignore`)
- Dùng `.env.example` làm template

