#include "joyc_hat.h"
#include "Arduino.h"

JoyCHat joyc;

JoyCHat::JoyCHat() {}

bool JoyCHat::begin() {
    Wire.begin(32, 33); // SDA=32, SCL=33 for M5Stack C Plus2
    delay(10);
    
    // Try first address (0x52 - Tetris uses this)
    Wire.beginTransmission(JOYC_I2C_ADDR_1);
    uint8_t error1 = Wire.endTransmission();
    if(error1 == 0) {
        _addr = JOYC_I2C_ADDR_1;
        _initialized = true;
        Serial.println("Joy-C hat detected at 0x52");
        return true;
    }
    
    // Try second address (0x54)
    Wire.beginTransmission(JOYC_I2C_ADDR_2);
    uint8_t error2 = Wire.endTransmission();
    if(error2 == 0) {
        _addr = JOYC_I2C_ADDR_2;
        _initialized = true;
        Serial.println("Joy-C hat detected at 0x54");
        return true;
    }
    
    Serial.println("Joy-C hat not found");
    _initialized = false;
    return false;
}

bool JoyCHat::isConnected() {
    if (!_initialized) return false;
    Wire.beginTransmission(_addr);
    return (Wire.endTransmission() == 0);
}

void JoyCHat::readBytes(uint8_t addr, uint8_t reg, uint8_t* buffer, uint8_t length) {
    uint8_t index = 0;
    Wire.beginTransmission(addr);
    Wire.write(reg);
    Wire.endTransmission();
    Wire.requestFrom(addr, length);
    for (int i = 0; i < length; i++) {
        buffer[index++] = Wire.read();
    }
}

uint16_t JoyCHat::getADCValue(uint8_t index) {
    if (!_initialized || index > 2) return 2048; // Return neutral value
    
    uint8_t data[2];
    uint8_t reg = index * 2 + ADC_VALUE_REG;
    readBytes(_addr, reg, data, 2);
    uint16_t value = data[0] | (data[1] << 8);
    return value;
}

bool JoyCHat::getButtonStatus() {
    if (!_initialized) return false;
    
    uint8_t data;
    readBytes(_addr, BUTTON_REG, &data, 1);
    return (data == 0); // Active low
}

// Tetris-style navigation functions with same thresholds
bool JoyCHat::checkUp() {
    return (getADCValue(POS_Y) > 2950);
}

bool JoyCHat::checkDown() {
    return (getADCValue(POS_Y) < 1600);
}

bool JoyCHat::checkLeft() {
    return (getADCValue(POS_X) < 1350);
}

bool JoyCHat::checkRight() {
    return (getADCValue(POS_X) > 2950);
}

bool JoyCHat::checkButton() {
    return getButtonStatus();
}

void JoyCHat::update() {
    // Could add debouncing or smoothing here if needed
}