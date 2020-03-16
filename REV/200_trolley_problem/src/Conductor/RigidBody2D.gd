extends RigidBody2D


# Declare member variables here. Examples:
# var a = 2
# var b = "text"
var parent

# Called when the node enters the scene tree for the first time.
func _ready():
	self.parent = get_node("..")
	

func body_entered(body):
	print("ENTERED")
	self.parent.get_node("AnimationPlayer").play("Death2")
# Called every frame. 'delta' is the elapsed time since the previous frame.
#func _process(delta):
#	pass
