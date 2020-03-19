# RE 100 - Dank Engine

| Author | novafacing |
| --- | --- |
| Point Value | 100 |
| Description | 2D GDScript Reversing |

This is probably the easiest of the three 100-point RE challenges. You're given a zip archive containing two files:

```
	DankEngine.x86_64
	DankEngine.pck
```

Spoiler: this is a stupid, tiny game made in Godot and exported with the lowest level of obfuscation: the scripts are readable instead of compiled! We just need to find them. If we open up the game you'll see some *ahem* nightmare fuel that you can control with WASD and jump around a little enclosed map. Astute gamers will notice that there's a path off to the right side of the map, but there's a wall in the way!

Unless you're way better at this game than I am, we're stuck now. So let's get into the RE part!

If you open the binary x86_64 in your disassembler of choice, you'll see a ton of Godot engine components, but it would definitely be above the 100 level to be looking for something to take advantage of in here. Instead, let's open the .pck file. This is the file Godot uses to store all the information about its Nodes, the basis of the engine's design. Below are some of the headers for these nodes:

```
	[node name="Environment" type="Node2D"]
	[node name="TileMap" type="TileMap" parent="."]
	[node name="Main" type="Node2D"]
	[node name="Player" parent="." instance=ExtResource( 1 )]
	[node name="Environment" parent="." instance=ExtResource( 2 )]
```

Under the "Player" node you'll notice there's a GDScript in plain text:

```
extends KinematicBody2D
# Constants and Enumerations
const GRAVITY                   = 348.0
const RUN_SPEED                 = 200.0
const JUMP_SPEED                = 224.0

# Global Variables
var g_direction
var g_velocity
var g_parent
var g_airborne
var g_delta
var g_cheat_stack
var g_god_mode
var key_evt_map = {
        "W":["up_evt_press","up_evt_release"],
        "A":["left_evt_press", "left_evt_release"],
        "S":["down_evt_press", "down_evt_release"],
        "D":["right_evt_press", "right_evt_release"],
        "Left":["left_action_evt_press", "left_action_evt_release"],
        "Right":["right_action_evt_press", "right_action_evt_release"],
        "Up":["up_action_evt_press", "up_action_evt_release"],
        "Down":["down_action_evt_press", "down_action_evt_release"],
        "P":["p_evt_press", "p_evt_release"],
        "U":["u_evt_press", "u_evt_release"],
        "R":["r_evt_press", "r_evt_release"],
        "G":["g_evt_press", "g_evt_release"],
        "0":["zero_evt_press", "zero_evt_release"]
}

# User-Defined Functions
func on_finished(anim_name):
        pass
        #print("N", anim_name)

func on_changed(old_name, new_name):
        pass
        #print(old_name, new_name)

func on_started(anim_name):
        pass
        #print("S", anim_name)

func generate_key_event(ev):
        if ev is InputEventKey and OS.get_scancode_string(ev.scancode) in self.key_evt_map:
                if ev.pressed:
                        self.call(self.key_evt_map[OS.get_scancode_string(ev.scancode)][0])
                else:
                        self.call(self.key_evt_map[OS.get_scancode_string(ev.scancode)][1])

func up_evt_press():
        Input.action_press("up")

func left_evt_press():
        Input.action_press("left")

func down_evt_press():
        Input.action_press("down")

func right_evt_press():
        Input.action_press("right")

func left_action_evt_press():
        Input.action_press("left_action")

func right_action_evt_press():
        Input.action_press("right_action")

func up_action_evt_press():
        Input.action_press("up_action")

func down_action_evt_press():
        Input.action_press("down_action")

func up_evt_release():
        Input.action_release("up")

func left_evt_release():
        Input.action_release("left")

func down_evt_release():
        Input.action_release("down")

func right_evt_release():
        Input.action_release("right")

func left_action_evt_release():
        Input.action_release("left_action")

func right_action_evt_release():
        Input.action_release("right_action")

func up_action_evt_release():
        Input.action_release("up_action")

func down_action_evt_release():
        Input.action_release("down_action")

# Cheat Code Events
func p_evt_press():
        self.g_cheat_stack.clear()

func p_evt_release():
        self.g_cheat_stack.push_back("P")

func u_evt_press():
        pass

func u_evt_release():
        self.g_cheat_stack.push_back("U")

func r_evt_press():
        pass

func r_evt_release():
        self.g_cheat_stack.push_back("R")

func g_evt_press():
        pass

func g_evt_release():
        self.g_cheat_stack.push_back("G")

func zero_evt_press():
        pass

func zero_evt_release():
        self.g_cheat_stack.push_back("0")
        if self.g_cheat_stack == ["P", "U", "R", "G", "0", "0"]:
                self.g_god_mode = not self.g_god_mode
                $CollisionShape2D.disabled = not $CollisionShape2D.disabled

# Ground Raycasting
func raycast_floor():
        return $RayCast2D.is_colliding()

func _ready():
        self.g_velocity = Vector2()
        self.g_parent = get_node("..")
        self.g_airborne = false
        self.g_cheat_stack = Array()
        self.g_god_mode = false

func _input(ev):
        self.generate_key_event(ev)

func _physics_process(delta):
        if Input.is_action_pressed("left"):
                self.g_velocity.x = -RUN_SPEED
        elif Input.is_action_pressed("right"):
                self.g_velocity.x = RUN_SPEED
        else:
                self.g_velocity.x = 0

        if Input.is_action_pressed("up") and not self.g_airborne and not self.g_god_mode:
                self.g_velocity.y -= JUMP_SPEED
                self.g_airborne = true

        if Input.is_action_pressed("up") and self.g_god_mode:
                self.g_velocity.y = -JUMP_SPEED
        elif Input.is_action_pressed("down") and self.g_god_mode:
                self.g_velocity.y = JUMP_SPEED
        elif self.g_god_mode:
                self.g_velocity.y = 0

        if not self.g_god_mode:
                self.g_velocity.y += GRAVITY * delta

        move_and_slide(self.g_velocity, Vector2(0, -1))

        if is_on_floor() or raycast_floor():
                if not self.g_god_mode:
                        self.g_velocity.y = GRAVITY * delta
                self.g_airborne = false
        else:
                self.g_airborne = true
```

A lot of this is pretty standard stuff, used for controlling the physics of the character. We can ignore all of that because what we really want is that g_god_mode flag to be toggled true so that:

```
$CollisionShape2D.disabled = not $CollisionShape2D.disabled
```

This will let us go through walls, because it'll disable the collision object associated with the Player. Seems like a good way to get over to that hidden area!

So, how do we enable god mode? Pretty easy:

We have this function, which handles key input and appropriately calls named functions based on the key map variable:

```
func generate_key_event(ev):
        if ev is InputEventKey and OS.get_scancode_string(ev.scancode) in self.key_evt_map:
                if ev.pressed:
                        self.call(self.key_evt_map[OS.get_scancode_string(ev.scancode)][0])
                else:
                        self.call(self.key_evt_map[OS.get_scancode_string(ev.scancode)][1])

```

This calls either the "pressed" or "released" function based on whether the key is being pressed or released. We know the release function for the zero key checks to see if g_cheat_stack is "PURG00", so we just need to make it that. 

```
# Cheat Code Events
func p_evt_press():
        self.g_cheat_stack.clear()

func p_evt_release():
        self.g_cheat_stack.push_back("P")

func u_evt_press():
        pass

func u_evt_release():
        self.g_cheat_stack.push_back("U")

func r_evt_press():
        pass

func r_evt_release():
        self.g_cheat_stack.push_back("R")

func g_evt_press():
        pass

func g_evt_release():
        self.g_cheat_stack.push_back("G")
```

Helpfully, pressing "P" clears the cheat stack variable so if you mess up you can try again. The rest of these handlers simply add the letter pressed to that array, so to make it c"PURG00", we simply have to type in that code and we're in god mode!

Now that you can go through walls and fly, just follow the path to where the flag is spelled out with blocks on the map!