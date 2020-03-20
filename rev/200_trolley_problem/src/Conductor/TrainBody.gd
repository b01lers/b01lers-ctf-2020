extends KinematicBody2D

const MOVEMENT_SPEED = 5000.0
const SLOWDOWN = 60.0

var key_evt_map = {
		"W":	["up_evt_press",	"up_evt_release"],
		"A":	["left_evt_press", 	"left_evt_release"],
		"S":	["down_evt_press", 	"down_evt_release"],
		"D":	["right_evt_press", "right_evt_release"],
		"Left":	["left_evt_press", 	"left_evt_release"],
		"Right":["right_evt_press", "right_evt_release"],
		"Up":	["up_evt_press", 	"up_evt_release"],
		"Down":	["down_evt_press", 	"down_evt_release"],
}

var velocity

func up_evt_press():
		Input.action_press("up")

func left_evt_press():
		Input.action_press("left")

func down_evt_press():
		Input.action_press("down")

func right_evt_press():
		Input.action_press("right")


func up_evt_release():
		Input.action_release("up")

func left_evt_release():
		Input.action_release("left")

func down_evt_release():
		Input.action_release("down")

func right_evt_release():
		Input.action_release("right")


		
func generate_key_event(ev):
		if ev is InputEventKey and OS.get_scancode_string(ev.scancode) in self.key_evt_map:
				if ev.pressed:
						self.call(self.key_evt_map[OS.get_scancode_string(ev.scancode)][0])
				else:
						self.call(self.key_evt_map[OS.get_scancode_string(ev.scancode)][1])

func face_right():
	$TrainSprite.rotation = deg2rad(0)
	$TrainSprite.flip_h = true
	get_node("TrainSprite/SmokeSprite").flip_h = true
	get_node("TrainSprite/SmokeSprite").position.x = -12
	
func face_left():
	$TrainSprite.rotation = deg2rad(0)
	$TrainSprite.flip_h = false
	get_node("TrainSprite/SmokeSprite").flip_h = false
	get_node("TrainSprite/SmokeSprite").position.x = 12

func face_up():
	if $TrainSprite.flip_h:
		$TrainSprite.rotation = deg2rad(-90)
	else:
		$TrainSprite.rotation = deg2rad(90)
		
func face_down():
	if $TrainSprite.flip_h:
		$TrainSprite.rotation = deg2rad(90)
	else:
		$TrainSprite.rotation = deg2rad(-90)

func _ready():
	$SmokeAnimationPlayer.play("Puff")
	self.velocity = Vector2()
	
func _input(ev):
	generate_key_event(ev)
	
func _process(delta):
	if Input.is_action_pressed("left"): # Go left
		face_left()
		self.velocity.x = -MOVEMENT_SPEED * delta
	elif Input.is_action_pressed("right"):
		face_right()
		self.velocity.x = MOVEMENT_SPEED * delta
	elif Input.is_action_pressed("up"):
		face_up()
		self.velocity.y = -MOVEMENT_SPEED * delta
	elif Input.is_action_pressed("down"):
		face_down()
		self.velocity.y = MOVEMENT_SPEED * delta
	else:
		self.velocity.x = 0
		self.velocity.y = 0
	
	move_and_slide(self.velocity, Vector2(0, -1))
