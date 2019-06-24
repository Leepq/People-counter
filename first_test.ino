#include <WiFi.h>
#include <Wire.h>
#include "esp_wifi.h"
#include <Adafruit_SSD1306.h>
#include <SPI.h>
#include <Adafruit_GFX.h>
#include <NTPClient.h>
#include <PCD8544.h>


#define maxCh 13                                                 // number of channels 
#define BL 27                                                    // backgorund light

static PCD8544 lcd = PCD8544(14,13,27,26,15);                    // LDC configuration 

int previousNumberPeople = -1;                                   // previous number of people detected in the room
int listcount = 0;                                               // total number of people detected in a certain period of time
int curChannel = 1;                                              // current channel scanned
int numberAP = 0;                                                // number of AP detected
String defaultTTL = "60";                                        // maaximum time elapsed before device is consirded offline

static const byte glyph[] = { B00010000, B00110100, B00110000, B00110100, B00010000 };


// struct used to keep information about APs
typedef struct {                              
  String name; 
  String mac;
}AP;

// array of APs detected
AP listAP[100];

// struct used to keep information about phones detected
typedef struct{
  String mac[3];
  long  nrAparitii = 1;
  long sumRSSI = 0;
  long medieRSSI = 0;
  unsigned long last_appereance = 0;
} package;

// array of phones detected
package list[300];

const wifi_promiscuous_filter_t filt={
    .filter_mask=WIFI_PROMIS_FILTER_MASK_MGMT|WIFI_PROMIS_FILTER_MASK_DATA
};

typedef struct { 
  int16_t mac[6];
} __attribute__((packed)) MacAddr;

typedef struct { 
  int16_t fctl;
  int16_t duration;
  MacAddr da;
  MacAddr sa;
  MacAddr bssid;
  int16_t seqctl;
  unsigned char payload[];
} __attribute__((packed)) WifiMgmtHdr;


// function which saves information about packages, being called everytime ESP32 detects one 
// the function verifies if the device is an AP or not and after that ifthe phone was detected before or not
// if the phone exists already in the array, then it calculates en average RSSI - distance of the signal
void sniffer(void* buf, wifi_promiscuous_pkt_type_t type) { //This is where packets end up after they get sniffed
  wifi_promiscuous_pkt_t *p = (wifi_promiscuous_pkt_t*)buf; 
  int len = p->rx_ctrl.sig_len;
  WifiMgmtHdr *wh = (WifiMgmtHdr*)p->payload;
  len -= sizeof(WifiMgmtHdr);
  if (len < 0){
    return;
  }
  String packet;
  String mac;
  int fctl = ntohs(wh->fctl);
  for(int i=8;i<=8+6+1;i++){ // This reads the first couple of bytes of the packet. You can read the whole packet replaceing the "8+6+1" with "p->rx_ctrl.sig_len"
     String aux = String(p->payload[i],HEX);
     if (aux.length() == 1) {
        packet += "0";
        packet += String(p->payload[i],HEX);
     }
     else {
        packet += String(p->payload[i],HEX);
     }
  }
  for(int i=4;i<=15;i++){ // This removes the 'nibble' bits from the stat and end of the data we want. So we only get the mac address.
    mac += packet[i];
  }
  mac.toUpperCase();
  
  int added = 0;
  for(int i=0;i<listcount;i++){ // checks if the MAC address has been added before
    if(mac == list[i].mac[0]){
      list[i].mac[1] = defaultTTL;
      if(list[i].mac[2] == "OFFLINE"){
        list[i].mac[2] = "0";
      }
      if(millis() - list[i].last_appereance > 2000){
        list[i].nrAparitii = list[i].nrAparitii + 1;
        list[i].last_appereance = millis();
        list[i].sumRSSI =  list[i].sumRSSI + p->rx_ctrl.rssi;    
        list[i].medieRSSI = round(list[i].sumRSSI/list[i].nrAparitii);
      }
      added = 1;
    }
  }
  int ap = 0;
  for(int i = 0; i < numberAP; i++) {
    if(mac == listAP[i].mac) {
      ap = 1;
    }
  }

  if(added == 0 && ap == 0){ // If its new an non-ap. add it to the array.
      list[listcount].last_appereance = millis();
      list[listcount].mac[0] = mac;
      list[listcount].mac[1] = defaultTTL;
      list[listcount].nrAparitii = 1;
      list[listcount].sumRSSI = p->rx_ctrl.rssi;
      list[listcount].medieRSSI = list[listcount].sumRSSI;
      listcount++;
      if(listcount >= 300){
        Serial.println("Too many addresses");
        listcount = 0;
      }
  }
}


String getValue(String data, char separator, int index)
{
    int found = 0;
    int strIndex[] = { 0, -1 };
    int maxIndex = data.length() - 1;

    for (int i = 0; i <= maxIndex && found <= index; i++) {
        if (data.charAt(i) == separator || i == maxIndex) {
            found++;
            strIndex[0] = strIndex[1] + 1;
            strIndex[1] = (i == maxIndex) ? i+1 : i;
        }
    }
    return found > index ? data.substring(strIndex[0], strIndex[1]) : "";
}

void setup() {
  // open serial communication
  Serial.begin(9600);

  // scan for APs
  int n = WiFi.scanNetworks();
  if (n > 0) {
    for (int i = 0; i < n; ++i) {
       listAP[i].name = WiFi.SSID(i);
       String mac;
       for(int j = 0; j < WiFi.BSSIDstr(i).length(); j=j+1) {
            mac += getValue( WiFi.BSSIDstr(i), ':', j);
       }
       listAP[i].mac = mac;
       delay(10);
       Serial.println(listAP[i].mac);
    }
  }
  numberAP = n;
  WiFi.disconnect(true);
  delay(3000);
  
  // lcd initial configuration
  lcd.begin(84, 48);
  pinMode(BL, OUTPUT);
  digitalWrite(BL, HIGH);
  lcd.createChar(0, glyph);

  // configurate ESP32 to scan for packages
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&sniffer);
  esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);
  Serial.println("starting!");

}

// function used to print information about a device
void print(int i) {    
      Serial.print(list[i].mac[0]);
      Serial.print("           ");
      Serial.print(list[i].medieRSSI);
      Serial.print("           ");       
      Serial.println(list[i].nrAparitii);
}

// function called after every verification of all 13 channels
// the function verifies if the number of people in the room changed or not and display it on the lcd
// in case a device is inactive for more than 30 minutes, then it is eliminated from the array
void setNumber() {
    int count = 0;                                               // number of people detected right now
    int countRoom = 0;                                           // number of people in the room detected right now

    // find the number of active devices 
    for(int i = 0; i < listcount; i++) {
     if(millis() - list[i].last_appereance < 1800000) {
         count++;
          if (list[i].medieRSSI > -65) {
            print(i);
            countRoom++;
          }
          else {
            Serial.print("*");
            print(i);
          }
     }
     else {
        for(int j = i; j < listcount - 1; j++) {
           list[j] = list[j+1];
        }
        listcount--;
      //  list[i].nrAparitii = 0;
      //  list[i].medieRSSI = 0;
      //  list[i].sumRSSI = 0;
       }
    }

    // display on lcd
    if(previousNumberPeople != countRoom) {
      Serial.print("ESP32 detecteaza ");
      Serial.print(count);
      Serial.println(" persoane");
      Serial.print("In incapere sunt aproximativ ");
      Serial.print(countRoom);
      Serial.println(" persoane.");
      // Write a piece of text on the first line...

      lcd.setCursor(3, 1);
      lcd.print("I spy with my ");
      lcd.setCursor(3, 2);
      lcd.print("  little eye  ");
      // Write the counter on the second line...
      lcd.setCursor(0, 3);
      lcd.print("      ");
      lcd.print(countRoom, DEC);
      lcd.print("      ");
      lcd.setCursor(0, 4);
      lcd.print("    people    ");

      lcd.setCursor(5, 0);
      lcd.write(0);
      lcd.setCursor(5, 4);
      lcd.write(0);
      lcd.setCursor(75, 0);
      lcd.write(0);
      lcd.setCursor(75, 4);
      lcd.write(0);

      if(countRoom > 5) {
      lcd.setCursor(40, 0);
      lcd.write(0);
      lcd.setCursor(40, 5);
      lcd.write(0);
      }

      if (countRoom > 10) {
      lcd.setCursor(5, 2);
      lcd.write(0);
      lcd.setCursor(75, 2);
      lcd.write(0);
      }
    }

    previousNumberPeople = countRoom;
}

void loop() {
    // check all 13 channes
    if(curChannel > maxCh){
      setNumber(); 
      curChannel = 1;
    }
    esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);  
    curChannel++;
    
    delay(200);

    
}
