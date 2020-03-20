extends Node2D

const static_check = [
	"4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
	"f5ca38f748a1d6eaf726b8a42fb575c3c71f1864a8143301782de13da2d9202b",
	"ec2e990b934dde55cb87300629cedfc21b15cd28bbcf77d8bbdc55359d7689da",
	"fa2b7af0a811b9acde602aacb78e3638e8506dfead5fe6c3425b10b526f94bdd",
	"82c01ce15b431d420eb6a1febfba7d7a2b69e5bcdcb929cb42cd3e9179d43fc4",
	"011af72a910ac4acf367eef9e6b761e0980842c30d4e9809840f4141d5163ede",
	"e7866fdc6672f827c76f6124ca3eeaff44aff8b7caf4ee1469b2ab887e7e7875",
	"9556b82499cc0aaf86aee7f0d253e17c61b7ef73d48a295f37d98f08b04ffa7f",
	"da4ea2a5506f2693eae190d9360a1f31793c98a1adade51d93533a6f520ace1c",
	"eb1e33e8a81b697b75855af6bfcdbcbf7cbbde9f94962ceaec1ed8af21f5a50f",
	"e629fa6598d732768f7c726b4b621285f9c3b85303900aa912017db7617d8bdb",
	"922c7954216ccfe7a61def609305ce1dc7c67e225f873f256d30d7a8ee4f404c",
	"4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce",
	"9556b82499cc0aaf86aee7f0d253e17c61b7ef73d48a295f37d98f08b04ffa7f",
	"6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
	"7902699be42c8a8e46fbbb4501726517e86b22c56a189f7625a6da49081b2451"

]

var soln = []

# Declare member variables here. Examples:
# var a = 2
# var b = "text"
onready var state = []



# Called when the node enters the scene tree for the first time.
func _ready():
	pass # Replace with function body.
	
func bin2dec(var binary_value):
	var decimal_value = 0
	var count = 0
	var temp

	while(binary_value != 0):
		temp = binary_value % 10
		binary_value /= 10
		decimal_value += temp * pow(2, count)
		count += 1

	return decimal_value
	
func vert(arr, index):
	var ret = []
	for memb in arr:
		ret.append(str(memb[index]))
	return ret
	
func check_solution():
	for i in range(len(state)):
		var ctx = HashingContext.new()
		ctx.start(HashingContext.HASH_MD5)
		var bin = PoolStringArray(state[i]).join("")
		var chval = str(bin2dec(int(bin)))
		soln.append(chval.sha256_text())
	for i in range(len(state)):
		var ctx = HashingContext.new()
		ctx.start(HashingContext.HASH_MD5)
		var bin = PoolStringArray(vert(state, i)).join("")
		var chval = str(bin2dec(int(bin)))
		soln.append(chval.sha256_text())
	for i in range(len(static_check)):
		if static_check[i] != soln[i]:
			get_tree().quit()
		else:
			print(soln[8].substr(8,2))
			print(soln[4].substr(10,2))
			print(soln[11].substr(6,2))
			print(soln[6].substr(47,2))
			print(soln[9].substr(14,2))
			
			print(soln[0].substr(26,2))
			print(soln[1].substr(17,2))
			print(soln[4].substr(34,2))
			print(soln[6].substr(3,2))
			print(soln[12].substr(3,2))
			print(soln[9].substr(56,2))
			
			print(soln[0].substr(7,2))
	
		
	
			
		
		
	

func flip(index):
	if len(state) == 0:
		var last_state = ["0", "0", "0", "0", "0", "0", "0", "0"]
		last_state[index] = "1"
		state.append(last_state)
	else:
		var last_state = state[-1].duplicate()
		last_state[index] = "1"
		state.append(last_state)
	if len(state) == 8:
		check_solution()
