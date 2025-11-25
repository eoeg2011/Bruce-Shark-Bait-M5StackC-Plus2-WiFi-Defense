#ifndef __ANTI_PREDATOR_MENU_H__
#define __ANTI_PREDATOR_MENU_H__

#include <MenuItemInterface.h>

class AntiPredatorMenu : public MenuItemInterface {
public:
    AntiPredatorMenu() : MenuItemInterface("Shark-Bait") {}

    void optionsMenu(void) override;
    void drawIcon(float scale = 1) override;
    void drawIconImg() override;
    bool getTheme() override { return false; } // Use simple icon, not theme image
};

#endif