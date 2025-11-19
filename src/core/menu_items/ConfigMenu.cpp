#include "ConfigMenu.h"
#include "core/display.h"
#include "core/i2c_finder.h"
#include "core/main_menu.h"
#include "core/settings.h"
#include "core/utils.h"
#include "core/wifi/wifi_common.h"
#ifdef HAS_RGB_LED
#include "core/led_control.h"
#endif

void ConfigMenu::optionsMenu() {
    options = {
        {"Brillo", setBrightnessMenu},
        {"Atenuación", setDimmerTimeMenu},
        {"Orientación", lambdaHelper(gsetRotation, true)},
        {"Color de UI", setUIColor},
        {"Tema de UI", setTheme},
        {String("Inicio rápido: " + String(bruceConfig.instantBoot ? "ON" : "OFF")),
         [=]() {
             bruceConfig.instantBoot = !bruceConfig.instantBoot;
             bruceConfig.saveFile();
         }},
#ifdef HAS_RGB_LED
        {"Color LED",
         [=]() {
             beginLed();
             setLedColorConfig();
         }},
        {"Efecto LED",
         [=]() {
             beginLed();
             setLedEffectConfig();
         }},
        {"Brillo LED",
         [=]() {
             beginLed();
             setLedBrightnessConfig();
         }},
        {"Parpadeo LED On/Off", setLedBlinkConfig},
#endif
        {"Sonido On/Off", setSoundConfig},
#if defined(HAS_NS4168_SPKR)
        {"Volumen de sonido", setSoundVolume},
#endif
        {"WiFi al arrancar", setWifiStartupConfig},
        {"App al arrancar", setStartupApp},
        {"Ocultar/Mostrar apps", []() { mainMenu.hideAppsMenu(); }},
        {"Credenciales de red", setNetworkCredsMenu},
        {"Reloj", setClock},
        {"Suspensión", setSleepMode},
        {"Restablecer fábrica", [=]() { bruceConfig.factoryReset(); }},
        {"Reiniciar", [=]() { ESP.restart(); }},
    };

    options.push_back({"Apagar", powerOff});
    options.push_back({"Sueño profundo", goToDeepSleep});

    if (bruceConfig.devMode) options.push_back({"Configurar pines del dispositivo", [=]() { devMenu(); }});

    options.push_back({"Acerca de", showDeviceInfo});
    addOptionToMainMenu();

    loopOptions(options, MENU_TYPE_SUBMENU, "Configuración");
}

void ConfigMenu::devMenu() {
    options = {
        {"Buscar I2C",  find_i2c_addresses                                   },
        {"Pines CC1101", [=]() { setSPIPinsMenu(bruceConfigPins.CC1101_bus); }},
        {"Pines NRF24", [=]() { setSPIPinsMenu(bruceConfigPins.NRF24_bus); } },
        {"Pines SDCard", [=]() { setSPIPinsMenu(bruceConfigPins.SDCARD_bus); }},
        //{"SYSI2C Pins", [=]() { setI2CPinsMenu(bruceConfigPins.sys_i2c); }   },
        {"Pines I2C",    [=]() { setI2CPinsMenu(bruceConfigPins.i2c_bus); }   },
        {"Pines UART",   [=]() { setUARTPinsMenu(bruceConfigPins.uart_bus); } },
        {"Pines GPS",    [=]() { setUARTPinsMenu(bruceConfigPins.gps_bus); }  },
        {"Atrás",        [=]() { optionsMenu(); }                             },
    };

    loopOptions(options, MENU_TYPE_SUBMENU, "Modo desarrollador");
}
void ConfigMenu::drawIconImg() {
    drawImg(
        *bruceConfig.themeFS(),
        bruceConfig.getThemeItemImg(bruceConfig.theme.paths.config),
        0,
        imgCenterY,
        true
    );
}
void ConfigMenu::drawIcon(float scale) {
    clearIconArea();
    int radius = scale * 9;

    int i = 0;
    for (i = 0; i < 6; i++) {
        tft.drawArc(
            iconCenterX,
            iconCenterY,
            3.5 * radius,
            2 * radius,
            15 + 60 * i,
            45 + 60 * i,
            bruceConfig.priColor,
            bruceConfig.bgColor,
            true
        );
    }

    tft.drawArc(
        iconCenterX,
        iconCenterY,
        2.5 * radius,
        radius,
        0,
        360,
        bruceConfig.priColor,
        bruceConfig.bgColor,
        false
    );
}
