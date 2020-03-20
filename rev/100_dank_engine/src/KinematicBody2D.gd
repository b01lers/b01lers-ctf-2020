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