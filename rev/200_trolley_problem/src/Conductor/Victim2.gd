extends Node2D

onready var Train = load("res://Train.tscn")
onready var Game = get_node("..")
# Declare member variables here. Examples:
# var a = 2
# var b = "text"


# Called when the node enters the scene tree for the first time.
func _ready():
	pass # Replace with function body.


# Called every frame. 'delta' is the elapsed time since the previous frame.
#func _process(delta):
#	pass


func _on_Area2D_body_entered(body):
	if body is KinematicBody2D:
		if $Skins/Sprite.visible:
			$AnimationPlayer.play("Death1")
			Game.flip(0)
		elif $Skins/Sprite2.visible:
			$AnimationPlayer.play("Death2")
			Game.flip(1)
		elif $Skins/Sprite3.visible:
			$AnimationPlayer.play("Death3")	
			Game.flip(2)
		elif $Skins/Sprite4.visible:
			$AnimationPlayer.play("Death4")	
			Game.flip(3)
		elif $Skins/Sprite5.visible:
			$AnimationPlayer.play("Death5")	
			Game.flip(4)
		elif $Skins/Sprite6.visible:
			$AnimationPlayer.play("Death6")	
			Game.flip(5)
		elif $Skins/Sprite7.visible:
			$AnimationPlayer.play("Death7")	
			Game.flip(6)
		elif $Skins/Sprite8.visible:
			$AnimationPlayer.play("Death8")	
			Game.flip(7)
