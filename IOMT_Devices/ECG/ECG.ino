/*
 ESP32 ECG IoT Node

 Sends ECG data to Raspberry Pi SDN Gateway

 Raspberry Pi:
 IP = 10.0.0.1

 ECG Endpoint:
 http://10.0.0.1:6000/ecg


 Demo Control:
 Raspberry Pi -> ESP32

 POST:
 http://ESP32_IP/mode

 {"mode":"normal"}
 {"mode":"attack"}

*/


#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <WebServer.h>


// ========================
// WiFi Configuration
// ========================

const char* WIFI_SSID = "IoT-Gateway";
const char* WIFI_PASSWORD = "";


// Raspberry Pi ECG Gateway

const char* SERVER_URL =
"http://10.0.0.1:6000/ecg";


// ThingSpeak

const char* THINGSPEAK_URL =
"https://api.thingspeak.com/update?api_key=EUMLXS3B9TRCOYW2&field1=0";


// ========================
// Patient
// ========================

const char* PATIENT_ID =
"P001";


// ========================
// ECG Parameters
// ========================

#define SAMPLE_INTERVAL 4
#define WINDOW_SIZE 50


float ecgWindow[WINDOW_SIZE];


// ========================
// Demo Trigger
// ========================

bool attackMode = false;


// ESP32 command server

WebServer server(80);


// ========================
// ECG Simulator
// Replace with ADC later
// ========================

float readECG()
{

    float ecg =
    random(-100,100)/1000.0;


    // Normal heartbeat variation

    if(random(0,25)==0)
    {
        ecg +=
        random(700,1200)/1000.0;
    }


    // Demo attack/anomaly mode

    if(attackMode)
    {
        ecg +=
        random(1500,2500)/1000.0;
    }


    return ecg;

}



// ========================
// Raspberry Pi Control
// ========================

void handleMode()
{

    if(server.hasArg("plain"))
    {

        StaticJsonDocument<200> doc;


        DeserializationError error =
        deserializeJson(
            doc,
            server.arg("plain")
        );


        if(error)
        {
            server.send(
                400,
                "application/json",
                "{\"error\":\"invalid json\"}"
            );

            return;
        }


        String mode =
        doc["mode"];


        if(mode == "attack")
        {
            attackMode = true;

            Serial.println(
                "DEMO ATTACK MODE ON"
            );
        }
        else
        {
            attackMode = false;

            Serial.println(
                "NORMAL MODE ON"
            );
        }


        server.send(
            200,
            "application/json",
            "{\"ok\":true}"
        );

    }

}



// ========================
// WiFi
// ========================

void connectWiFi()
{

    WiFi.mode(WIFI_STA);


    WiFi.begin(
        WIFI_SSID,
        WIFI_PASSWORD
    );


    Serial.print(
        "Connecting"
    );


    while(
        WiFi.status()!=WL_CONNECTED
    )
    {

        delay(500);

        Serial.print(".");

    }


    Serial.println();

    Serial.println(
        "WiFi Connected"
    );


    Serial.print(
        "ESP IP: "
    );


    Serial.println(
        WiFi.localIP()
    );

}



// ========================
// Send ECG Window
// ========================

void sendECG()
{

    if(
        WiFi.status()!=WL_CONNECTED
    )
    {
        connectWiFi();
    }


    HTTPClient http;


    http.begin(
        SERVER_URL
    );


    http.addHeader(
        "Content-Type",
        "application/json"
    );


    StaticJsonDocument<4096> doc;


    doc["patient_id"]
    =
    PATIENT_ID;


    doc["device_mac"]
    =
    WiFi.macAddress();


    doc["device_ip"]
    =
    WiFi.localIP().toString();


    doc["sampling_rate"]
    =
    250;



    JsonArray ecg =
    doc.createNestedArray(
        "ecg_window"
    );


    for(
        int i=0;
        i<WINDOW_SIZE;
        i++
    )
    {
        ecg.add(
            ecgWindow[i]
        );
    }



    String json;


    serializeJson(
        doc,
        json
    );


    Serial.println(json);



    int response =
    http.POST(
        json
    );


    Serial.print(
        "Server:"
    );


    Serial.println(
        response
    );


    http.end();

}



// ========================
// ThingSpeak
// ========================

void sendThingSpeak()
{

    if(
        WiFi.status()!=WL_CONNECTED
    )
    {
        connectWiFi();
    }


    HTTPClient http;


    http.begin(
        THINGSPEAK_URL
    );


    int response =
    http.GET();


    Serial.print(
        "ThingSpeak:"
    );


    Serial.println(
        response
    );


    http.end();

}



// ========================
// Setup
// ========================

void setup()
{

    Serial.begin(115200);


    randomSeed(
        esp_random()
    );


    connectWiFi();



    // Raspberry Pi control endpoint

    server.on(
        "/mode",
        HTTP_POST,
        handleMode
    );


    server.begin();


    Serial.println(
        "ESP32 control ready"
    );

}



// ========================
// Loop
// ========================

void loop()
{

    server.handleClient();



    for(
        int i=0;
        i<WINDOW_SIZE;
        i++
    )
    {

        ecgWindow[i]
        =
        readECG();


        delay(
            SAMPLE_INTERVAL
        );

    }



    sendECG();


    sendThingSpeak();

}