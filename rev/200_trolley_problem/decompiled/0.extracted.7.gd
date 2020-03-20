extends Node2D








func _ready():
	pass
	
func body_entered(body):
	$AnimationPlayer.play("Death2")
	
