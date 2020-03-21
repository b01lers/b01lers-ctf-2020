extends Area2D








func _ready():
	pass





func _on_Train_body_enter():
	print("ENTERED")
	get_node("../AnimationPlayer").play("Death1")

