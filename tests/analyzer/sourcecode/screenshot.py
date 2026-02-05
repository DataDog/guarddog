""" Tests for screenshot detection rule

    RULEID cases:
      - PIL ImageGrab.grab()
      - pyscreenshot library
      - pyautogui screenshot
      - mss library (various patterns)
      - D3DShot (Windows DirectX screenshots)
"""

####################
# PIL ImageGrab    #
####################

from PIL import ImageGrab

# ruleid: screenshot
screenshot = ImageGrab.grab()
screenshot.save("screen.png")

# ruleid: screenshot
img = ImageGrab.grab(bbox=(0, 0, 1920, 1080))


####################
# PIL full path    #
####################

import PIL.ImageGrab

# ruleid: screenshot
screen = PIL.ImageGrab.grab()


####################
# pyscreenshot     #
####################

import pyscreenshot

# ruleid: screenshot
img = pyscreenshot.grab()
img.save("capture.png")

# ruleid: screenshot
region = pyscreenshot.grab(bbox=(10, 10, 500, 500))


####################
# pyautogui        #
####################

import pyautogui

# ruleid: screenshot
screenshot = pyautogui.screenshot()

# ruleid: screenshot
region = pyautogui.screenshot(region=(0, 0, 300, 400))

# ruleid: screenshot
pyautogui.screenshot("my_screenshot.png")


####################
# mss library      #
####################

import mss

# ruleid: screenshot
sct_img = mss.mss().grab(mss.mss().monitors[1])

# ruleid: screenshot
with mss.mss() as sct:
    monitor = sct.monitors[1]
    # ruleid: screenshot
    sct.grab(monitor)

# ruleid: screenshot
sct = mss.mss()
monitor = {"top": 0, "left": 0, "width": 800, "height": 600}
# ruleid: screenshot
sct.grab(monitor)


####################
# D3DShot          #
####################

import d3dshot

# ruleid: screenshot
d3dshot.create(capture_output="numpy").screenshot()

# ruleid: screenshot
d = d3dshot.create()
d.screenshot()

# ruleid: screenshot
capture = d3dshot.create(capture_output="pil")
monitor = capture.displays[0]
capture.screenshot()
