extends RigidBody2D





var parent


func _ready():
	self.parent = get_node("..")
	

func body_entered(body):
	print("ENTERED")
	self.parent.get_node("AnimationPlayer").play("Death2")



