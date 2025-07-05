#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <crow.h>
#include "json.hpp"

using json = nlohmann::json;

// Global variables
std::unordered_map<std::string, bool> inventoryStatus;
std::vector<json> incidents;
std::mutex incidents_mutex;
std::mutex inventory_mutex;

// Helper functions
std::string generateIncidentId() {
    auto now = std::chrono::system_clock::now();
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    return "INC-" + std::to_string(now_ms.count());
}

void logIncident(const json& incident) {
    std::lock_guard<std::mutex> lock(incidents_mutex);
    
    json incidentObj;
    try {
        incidentObj["id"] = generateIncidentId();
        incidentObj["timestamp"] = incident.at("timestamp").get<std::string>();
        incidentObj["attackType"] = incident.at("attackType").get<std::string>();
        incidentObj["payload"] = incident.at("payload").get<std::string>();
        
        // Optional fields with defaults
        incidentObj["bypassReason"] = incident.value("bypassReason", "none");
        incidentObj["detectedURL"] = incident.value("detectedURL", "");
        incidentObj["simulatedUserID"] = incident.value("simulatedUserID", "");
        incidentObj["simulatedUserIP"] = incident.value("simulatedUserIP", "");
        incidentObj["userAgent"] = incident.value("userAgent", "");
        incidentObj["referrer"] = incident.value("referrer", "");
        incidentObj["affectedElement"] = incident.value("affectedElement", "");
        incidentObj["actionTriggered"] = incident.value("actionTriggered", "none");
        incidentObj["status"] = "reported";
        
        if (incident.contains("productId") && incident.contains("productName")) {
            incidentObj["productId"] = incident["productId"].get<std::string>();
            incidentObj["productName"] = incident["productName"].get<std::string>();
        }
        
        if (incident.contains("recommendations")) {
            json recs = json::array();
            for (const auto& rec : incident["recommendations"]) {
                recs.push_back(rec.get<std::string>());
            }
            incidentObj["recommendations"] = recs;
        }
        
        if (incident.contains("vulnerableCode")) {
            incidentObj["vulnerableCode"] = incident["vulnerableCode"].get<std::string>();
            incidentObj["fixedCode"] = incident["fixedCode"].get<std::string>();
            incidentObj["filePath"] = incident["filePath"].get<std::string>();
            incidentObj["lineNumber"] = incident["lineNumber"].get<int>();
        }
        
        incidents.push_back(incidentObj);
        std::cout << "New incident logged: " << incidentObj.dump(2) << std::endl;
    } catch (const json::exception& e) {
        std::cerr << "JSON error in logIncident: " << e.what() << std::endl;
        throw;
    }
}

struct CORSMiddleware {
    struct context {};
    
    void before_handle(crow::request& req, crow::response& res, context& ctx) {
        res.add_header("Access-Control-Allow-Origin", "*");
        res.add_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
        res.add_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.add_header("Access-Control-Max-Age", "86400");
        
        if (req.method == "OPTIONS"_method) {
            res.code = 200;
            res.end();
        }
    }
    
    void after_handle(crow::request& req, crow::response& res, context& ctx) {
        // Add CORS headers to all responses
        res.add_header("Access-Control-Allow-Origin", "*");
    }
};

int main() {
    // Initialize inventory
    {
        std::lock_guard<std::mutex> lock(inventory_mutex);
        for (int i = 1; i <= 10; i++) {
            std::string id = "PROD_00" + std::to_string(i);
            if (i >= 10) id = "PROD_0" + std::to_string(i);
            inventoryStatus[id] = true;
        }
    }

    crow::App<CORSMiddleware> app;

    // Add OPTIONS handlers for each endpoint
    CROW_ROUTE(app, "/api/trigger_security_incident")
    .methods("OPTIONS"_method)
    ([]() {
        return crow::response(200);
    });

    CROW_ROUTE(app, "/api/incidents")
    .methods("OPTIONS"_method)
    ([]() {
        return crow::response(200);
    });

    CROW_ROUTE(app, "/api/inventory")
    .methods("OPTIONS"_method)
    ([]() {
        return crow::response(200);
    });

    CROW_ROUTE(app, "/health")
    .methods("OPTIONS"_method)
    ([]() {
        return crow::response(200);
    });

    // Incident reporting endpoint
    CROW_ROUTE(app, "/api/trigger_security_incident")
    .methods("POST"_method)
    ([](const crow::request& req) {
        auto res = crow::response();
        
        try {
            if (req.get_header_value("Content-Type") != "application/json") {
                res.code = 415;
                res.body = "Content-Type must be application/json";
                return res;
            }

            json incident;
            try {
                incident = json::parse(req.body);
            } catch (const json::parse_error& e) {
                res.code = 400;
                res.body = "Invalid JSON: " + std::string(e.what());
                return res;
            }

            const std::vector<std::string> required = {"attackType", "payload", "timestamp"};
            for (const auto& field : required) {
                if (!incident.contains(field)) {
                    res.code = 400;
                    res.body = "Missing required field: " + field;
                    return res;
                }
            }

            logIncident(incident);

            if (incident.contains("productId")) {
                std::string productId = incident["productId"].get<std::string>();
                std::lock_guard<std::mutex> lock(inventory_mutex);
                if (inventoryStatus.find(productId) != inventoryStatus.end()) {
                    inventoryStatus[productId] = false;
                }
            }

            res.code = 200;
            res.body = json{
                {"status", "success"},
                {"message", "Incident logged successfully"}
            }.dump();
            res.add_header("Content-Type", "application/json");

        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            res.code = 500;
            res.body = "Internal server error";
        }

        return res;
    });

    // Get all incidents
    CROW_ROUTE(app, "/api/incidents")
    .methods("GET"_method)
    ([](const crow::request& req) {
        auto res = crow::response();
        std::lock_guard<std::mutex> lock(incidents_mutex);
        res.body = json{{"incidents", incidents}}.dump();
        res.add_header("Content-Type", "application/json");
        res.code = 200;
        return res;
    });

    // Get inventory status
    CROW_ROUTE(app, "/api/inventory")
    .methods("GET"_method)
    ([](const crow::request& req) {
        auto res = crow::response();
        std::lock_guard<std::mutex> lock(inventory_mutex);
        json inventoryJson;
        for (const auto& item : inventoryStatus) {
            inventoryJson[item.first] = item.second;
        }
        res.body = inventoryJson.dump();
        res.add_header("Content-Type", "application/json");
        res.code = 200;
        return res;
    });

    // Health check
    CROW_ROUTE(app, "/health")
    ([]{
        auto res = crow::response("Unified Sentinel Backend Operational");
        res.code = 200;
        return res;
    });

    std::cout << "Unified Sentinel Backend running on http://localhost:8080\n";
    app.port(8080).multithreaded().run();
    return 0;
}