extends Control

onready  var tie = get_node("../Panel/TextInterfaceEngine")






func _ready():
	tie.reset()
	tie.set_color(Color(1, 1, 1))
	tie.buff_text("This is a song, ", 0.1)
	tie.buff_text("lalala
", 0.2)
	tie.buff_silence(1)
	tie.buff_text("Goodbye!", 0.1)
	tie.set_state(tie.STATE_OUTPUT)





