extends Control

onready var tie = get_node("Panel/TextInterfaceEngine")
# Declare member variables here. Examples:
# var a = 2
# var b = "text"


# Called when the node enters the scene tree for the first time.
func _ready():
	tie.reset()
	tie.set_color(Color(1,1,1))
	tie.buff_text("This is a song, ", 0.1)
	tie.buff_text("lalala\n", .2)
	tie.buff_silence(1)
	tie.buff_text("Goodbye!", .1)
	tie.set_state(tie.STATE_OUTPUT)


# Called every frame. 'delta' is the elapsed time since the previous frame.
#func _process(delta):
#	pass
