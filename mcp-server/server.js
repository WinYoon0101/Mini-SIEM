import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import axios from "axios";

// 1. Khởi tạo MCP Server
const server = new Server(
    {
        name: "Mini-SIEM-Agent",
        version: "1.0.0",
    },
    {
        capabilities: { tools: {} },
    }
);

// Trỏ tới FastAPI đang được expose qua port 8000 từ Docker
const API_BASE = "http://localhost:8000";

// 2. Khai báo danh sách Tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
        tools: [
            {
                name: "siem_health_check",
                description: "Kiểm tra trạng thái của toàn bộ hệ thống SIEM (API, Redis, Elasticsearch).",
                inputSchema: { type: "object", properties: {} }
            },
            {
                name: "siem_search_logs",
                description: "Tìm kiếm log bảo mật. Có thể lọc theo keyword, IP, loại sự kiện (event_type), hoặc mức độ nguy hiểm (severity).",
                inputSchema: {
                    type: "object",
                    properties: {
                        q: { type: "string", description: "Từ khóa tìm kiếm (full-text)" },
                        event_type: { type: "string", description: "VD: web_access, firewall_block, ids_alert" },
                        severity_min: { type: "number", description: "Mức độ nguy hiểm tối thiểu (1-5)" },
                        src_ip: { type: "string", description: "IP nguồn" },
                        size: { type: "number", description: "Số lượng kết quả trả về (mặc định 10)" }
                    }
                }
            },
            {
                name: "siem_get_stats",
                description: "Lấy báo cáo thống kê tổng quan về hệ thống: tổng log, số cuộc tấn công, top IP tấn công.",
                inputSchema: { type: "object", properties: {} }
            }
        ],
    };
});

// 3. Xử lý Logic khi AI gọi Tool
server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
        let resultData;

        switch (name) {
            case "siem_health_check":
                const healthRes = await axios.get(`${API_BASE}/health`);
                resultData = healthRes.data;
                break;

            case "siem_search_logs":
                // Map các tham số AI truyền vào thành query string cho FastAPI
                const searchParams = {
                    q: args?.q,
                    event_type: args?.event_type,
                    severity_min: args?.severity_min,
                    src_ip: args?.src_ip,
                    size: args?.size || 10
                };
                const searchRes = await axios.get(`${API_BASE}/search`, { params: searchParams });
                resultData = searchRes.data;
                break;

            case "siem_get_stats":
                const statsRes = await axios.get(`${API_BASE}/stats`);
                resultData = statsRes.data;
                break;

            default:
                throw new Error(`Tool không tồn tại: ${name}`);
        }

        return {
            content: [{ type: "text", text: JSON.stringify(resultData, null, 2) }],
        };

    } catch (error) {
        return {
            content: [{
                type: "text", 
                text: `Lỗi kết nối SIEM API: ${error.message}. FastAPI ở cổng 8000 có đang chạy không?`
            }],
            isError: true,
        };
    }
});

// 4. Mở kết nối STDIO
async function runServer() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("Mini SIEM MCP Server is running...");
}

runServer().catch(console.error);