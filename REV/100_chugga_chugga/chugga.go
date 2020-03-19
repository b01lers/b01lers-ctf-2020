package main
// pctf{s4d_chugg4_n01zez}

import "fmt"
//import "strings"
//import "math"
import "os"

func fail() {
	fmt.Println("Boom! You are dead. You come back to life in the next car.")
}

func win() {
	fmt.Println("You've done it! You've saved the train!");
	os.Exit(1)
}
func main() {
	var chrlist string
	car_count := 0
	for true {
		fmt.Println("We're in train car: ", car_count)
		fmt.Println("The door is locked, but luckily, you're the conductor! Input your code: ")
		fmt.Scan(&chrlist)
		if (chrlist[2] != 't' || chrlist[9] != 'c' || chrlist[16] != 'n' || chrlist[21] != 'z' || chrlist[22] != '}' || chrlist[5] != chrlist[2] - 1 || chrlist[2] ^ chrlist[3] != 18 || chrlist[1] != chrlist[9] || chrlist[1] != chrlist[7] - 1 || chrlist[12] != chrlist[13] || chrlist[19] ^ chrlist[21] != 0 || chrlist[14] - '0' + chrlist[6] - '0' != 8 || chrlist[4] != chrlist[22] - 2 || chrlist[8] != chrlist[15] || chrlist[8] + 4 != chrlist[1] || chrlist[22] - chrlist[17] + 40 != chrlist[11] || chrlist[11] - chrlist[5] - chrlist[18] + chrlist[17] != chrlist[18] - chrlist[17] || chrlist[0] != chrlist[16] + ((chrlist[18] - chrlist[17]) * ((chrlist[6] - chrlist[17])  / 2)) || chrlist[10] != chrlist[13] + 1 || chrlist[10] != (((chrlist[4] - chrlist[7]) * 4) + (2 * (chrlist[6] - chrlist[17]))) + ((chrlist[6] - chrlist[17])) || 2 * (chrlist[18] - chrlist[17]) != chrlist[20] - chrlist[1] || chrlist[5] ^ chrlist[16] != 29 || chrlist[6] - chrlist[17] != (chrlist[18] - chrlist[17]) * 4 || chrlist[6] != chrlist[14]) {
			fail()
			car_count++
		} else {
			win()
		}
	}

}
/*

chrlist[2] != 't' 
chrlist[9] != 'c' 
chrlist[16] != 'n' 
chrlist[21] != 'z' 
chrlist[22] != '}' 
chrlist[5] != chrlist[2] - 1 
chrlist[2] ^ chrlist[3] != 18 
chrlist[1] != chrlist[9] 
chrlist[1] != chrlist[7] - 1 
chrlist[12] != chrlist[13] 
chrlist[19] ^ chrlist[21] != 0 
chrlist[14] - '0' + chrlist[6] - '0' != 8 
chrlist[4] != chrlist[22] - 2 
chrlist[8] != chrlist[15] 
chrlist[8] + 4 != chrlist[1] 
chrlist[22] - chrlist[17] + 40 != chrlist[11] 
chrlist[11] - chrlist[5] - chrlist[18] + chrlist[17] != chrlist[18] - chrlist[17] 
chrlist[0] != chrlist[16] + ((chrlist[18] - chrlist[17]) * ((chrlist[6] - chrlist[17])  / 2)) 
chrlist[10] != chrlist[13] + 1 
chrlist[10] != (((chrlist[4] - chrlist[7]) * 4) + (2 * (chrlist[6] - chrlist[17]))) + ((chrlist[6] - chrlist[17])) 
2 * (chrlist[18] - chrlist[17]) != chrlist[20] - chrlist[1] 
chrlist[5] ^ chrlist[16] != 29 
chrlist[6] - chrlist[17] != (chrlist[18] - chrlist[17]) * 4 
chrlist[6] != chrlist[14]

*/
