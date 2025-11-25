#ifndef __JOYC_HAT_H__
#define __JOYC_HAT_H__

#include <Wire.h>

// Try both common Joy-C addresses
#define JOYC_I2C_ADDR_1 0x52  // Common address
#define JOYC_I2C_ADDR_2 0x54  // Alternative address
#define ADC_VALUE_REG        0x00
#define POS_VALUE_REG_10_BIT 0x10
#define POS_VALUE_REG_8_BIT  0x20
#define BUTTON_REG           0x30

#define POS_X 0
#define POS_Y 1

class JoyCHat {
public:
    JoyCHat();
    bool begin();
    bool isConnected();
    
    // Tetris-style ADC reading
    uint16_t getADCValue(uint8_t index);
    bool getButtonStatus();
    
    // Navigation functions (Tetris-style thresholds)
    bool checkUp();      // Y > 2950
    bool checkDown();    // Y < 1600  
    bool checkLeft();    // X < 1350
    bool checkRight();   // X > 2950
    bool checkButton();  // Button pressed
    
    void update();

private:
    bool _initialized = false;
    uint8_t _addr = JOYC_I2C_ADDR_1;
    void readBytes(uint8_t addr, uint8_t reg, uint8_t* buffer, uint8_t length);
};

extern JoyCHat joyc;

#endif