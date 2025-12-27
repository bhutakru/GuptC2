from Core import color
import time
import sys
import os

def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_slow(text, delay=0.02):
    """Print text character by character"""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)

def animate_sneaky():
    """Animated sneaky figure walking across screen"""
    width = 60
    
    # Sneaky walking frames
    frames = [
        "    🕵️ ",
        "   🕵️  ",
        "  🕵️   ",
        " 🕵️    ",
    ]
    
    # Alternative ASCII sneaky figure if emoji doesn't work well
    ascii_frames = [
        r"   .-.",
        r"  (o.o)",
        r"   |>",
        r"  /| ",
    ]
    
    sneaky_walk = [
        r"      ▄▀▀▀▄   ",
        r"     █ ◕ ◕█   ",
        r"      █▄▄▄█▄  ",
        r"       █ █    ",
        r"      ▄█ █▄   ",
    ]
    
    # Simple walking animation
    print()
    for i in range(12):
        spaces = " " * (i * 4)
        if i % 2 == 0:
            walker = spaces + color.cyan("  ░░░░") + color.yellow("▓▓") + color.cyan("░░")
        else:
            walker = spaces + color.cyan(" ░░░░") + color.yellow("▓▓") + color.cyan("░░ ")
        sys.stdout.write(f"\r{walker}   ")
        sys.stdout.flush()
        time.sleep(0.08)
    
    print("\r" + " " * 70)  # Clear line

def animate_gupt_text():
    """Animate GUPT text appearing"""
    gupt_art = [
        "    ██████╗ ██╗   ██╗██████╗ ████████╗",
        "   ██╔════╝ ██║   ██║██╔══██╗╚══██╔══╝",
        "   ██║  ███╗██║   ██║██████╔╝   ██║   ",
        "   ██║   ██║██║   ██║██╔═══╝    ██║   ",
        "   ╚██████╔╝╚██████╔╝██║        ██║   ",
        "    ╚═════╝  ╚═════╝ ╚═╝        ╚═╝   ",
    ]
    
    # Reveal line by line with color
    for line in gupt_art:
        print(color.red("    ║") + color.cyan(line) + "                   " + color.red("║"))
        time.sleep(0.1)

def print_banner():
    """Print animated GuptC2 banner"""
    
    # Clear screen first
    clear_screen()
    
    # Show sneaky intro
    print(color.yellow("\n    [ Initializing Stealth Mode... ]"))
    time.sleep(0.3)
    
    # Sneaky figure walking
    print(color.cyan("\n    Sneaking in..."))
    animate_sneaky()
    
    time.sleep(0.2)
    
    # Top border animation
    border = "    ╔══════════════════════════════════════════════════════════════╗"
    print_slow(color.red(border) + "\n", 0.008)
    print(color.red("    ║") + "                                                              " + color.red("║"))
    
    # Animated GUPT text
    gupt_lines = [
        ("    ██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗██████╗         ", 0.05),
        ("   ██╔════╝ ██║   ██║██╔══██╗╚══██╔══╝██╔════╝╚════██╗        ", 0.05),
        ("   ██║  ███╗██║   ██║██████╔╝   ██║   ██║      █████╔╝        ", 0.05),
        ("   ██║   ██║██║   ██║██╔═══╝    ██║   ██║     ██╔═══╝         ", 0.05),
        ("   ╚██████╔╝╚██████╔╝██║        ██║   ╚██████╗███████╗        ", 0.05),
        ("    ╚═════╝  ╚═════╝ ╚═╝        ╚═╝    ╚═════╝╚══════╝        ", 0.05),
    ]
    
    for line, delay in gupt_lines:
        print(color.red("    ║") + color.cyan(line) + color.red("║"))
        time.sleep(delay)
    
    print(color.red("    ║") + "                                                              " + color.red("║"))
    
    # Stealth mode text with typing effect
    stealth_text = "            [ S T E A L T H   M O D E ]                       "
    print(color.red("    ║"), end="")
    print_slow(color.yellow(stealth_text), 0.02)
    print(color.red("║"))
    
    # Info lines
    print(color.red("    ║") + "                                                              " + color.red("║"))
    
    tagline = "   Command & Control Framework v2.0                           "
    print(color.red("    ║"), end="")
    print_slow(color.green(tagline), 0.015)
    print(color.red("║"))
    
    features = "   Hidden | Silent | Deadly                                   "
    print(color.red("    ║"), end="")
    print_slow(color.yellow(features), 0.015)
    print(color.red("║"))
    
    print(color.red("    ║") + "                                                              " + color.red("║"))
    
    author = "   Author: Rushabh Bhutak                                     "
    print(color.red("    ║") + color.blue(author) + color.red("║"))
    
    # Bottom border
    border_bottom = "    ╚══════════════════════════════════════════════════════════════╝"
    print_slow(color.red(border_bottom), 0.008)
    
    # Final sneaky message
    print()
    print_slow(color.cyan("    🔇 "), 0.05)
    print_slow(color.yellow("Operating in the shadows..."), 0.03)
    print_slow(color.cyan(" 🔇\n"), 0.05)
    time.sleep(0.3)
    print()


def print_banner_simple():
    """Non-animated version for quick start"""
    print(
        "\n" +
        color.red("    ╔══════════════════════════════════════════════════════════════╗") + "\n" +
        color.red("    ║") + "                                                              " + color.red("║") + "\n" +
        color.red("    ║") + color.cyan("    ██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗██████╗         ") + color.red("║") + "\n" +
        color.red("    ║") + color.cyan("   ██╔════╝ ██║   ██║██╔══██╗╚══██╔══╝██╔════╝╚════██╗        ") + color.red("║") + "\n" +
        color.red("    ║") + color.cyan("   ██║  ███╗██║   ██║██████╔╝   ██║   ██║      █████╔╝        ") + color.red("║") + "\n" +
        color.red("    ║") + color.cyan("   ██║   ██║██║   ██║██╔═══╝    ██║   ██║     ██╔═══╝         ") + color.red("║") + "\n" +
        color.red("    ║") + color.cyan("   ╚██████╔╝╚██████╔╝██║        ██║   ╚██████╗███████╗        ") + color.red("║") + "\n" +
        color.red("    ║") + color.cyan("    ╚═════╝  ╚═════╝ ╚═╝        ╚═╝    ╚═════╝╚══════╝        ") + color.red("║") + "\n" +
        color.red("    ║") + "                                                              " + color.red("║") + "\n" +
        color.red("    ║") + color.yellow("            [ S T E A L T H   M O D E ]                       ") + color.red("║") + "\n" +
        color.red("    ║") + "                                                              " + color.red("║") + "\n" +
        color.red("    ║") + color.green("   Command & Control Framework v2.0                           ") + color.red("║") + "\n" +
        color.red("    ║") + color.yellow("   Hidden | Silent | Deadly                                   ") + color.red("║") + "\n" +
        color.red("    ║") + "                                                              " + color.red("║") + "\n" +
        color.red("    ║") + color.blue("   Author: Rushabh Bhutak                                     ") + color.red("║") + "\n" +
        color.red("    ╚══════════════════════════════════════════════════════════════╝") + "\n\n"
    )
