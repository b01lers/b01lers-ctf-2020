#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

extern uint64_t hash(char input, int pos);
extern struct tnode * init_shadow(void * pseudostack, char * input);
extern void populate_shadow(struct tnode * root, char * input);

struct tnode {
	struct tnode * parent;
	struct tnode * left;
	struct tnode * right;

	char data;
	int64_t h;
};

void tree_add(struct tnode * root, struct tnode * node) {
	if (node->h > root->h) {
		if (root->right == NULL) {
			root->right = node;
			node->parent = root;
		} else{
			tree_add(root->right, node);
		}
	} else if (node->h < root->h) {
		if (root->left == NULL) {
			root->left = node;
			node->parent = root;
		}
		tree_add(root->left, node);
	}
}

void print_tree(struct tnode * root) {
	printf("Oh no! our map broke...I'll try to get it working, sit tight!\n");
	//sleep(root->h);
	if (root->left != NULL) {
		print_tree(root->left);
	} 
	if (root->right != NULL) {
		print_tree(root->right);
	}
	printf("Here's a map fragment: %c %lx\n", root->data, root->h);
}

void free_tree(struct tnode * root) {
	if (root->left != NULL) {
		free_tree(root->left);
	} else if (root->right != NULL) {
		free_tree(root->right);
	} else if (root->left == NULL && root->right == NULL) {
		if (root->parent != NULL) {
			if (root->parent->left == root) {
				root->parent->left = NULL;
			} else if (root->parent->right == root) {
				root->parent->right = NULL;
			}
		}
		free(root);
	}
}


/* pctf{w3ll_z3ld4_cut_h3r_h4ir_in_b0tw_gu3ss_1ll_sh00t_my_sh0t_w1th_g4n0nd0rf} */
int main(int argc, char ** argv) {

	if (argc < 2) {
		printf("Well you gotta give me something!\n");
		printf("Usage: ./spirit_tracks <input>\n");
		exit(1);
	}
	printf("Welcome to Zoulda's Spirit Train Station! We've taken your ticket (id: %s)\n"
		   " and we'll board you shortly! But first, here's a map. Use it go get to the platform!\n", argv[1]);
	char * option = argv[1];
	void * pseudostack = calloc(1, 4096);
	init_shadow(pseudostack, argv[2]);
	populate_shadow(pseudostack, argv[2]);

	struct tnode * root = (struct tnode *)calloc(1, sizeof(struct tnode));
	root->parent = NULL;
	root->left = NULL;
	root->right = NULL;
	root->data = argv[1][0];
	root->h = hash(root->data, 1);


	for (int i = 1; i < strlen(option); i++) {
		struct tnode * node = (struct tnode *)calloc(1, sizeof(struct tnode));
		node->data = argv[1][i];
		node->h = hash(node->data, i + 1);
		tree_add(root, node); 
	}
	print_tree(root);
	//print_tree(pseudostack);
	FILE * fp = fopen("memdump", "rb");
	FILE * fpo = fopen("memdumpo", "wb");
	char * mem = (char *)calloc(1, 4096);
	fread(mem, 1, 4096, fp);
	fwrite(pseudostack, 4096, 1, fpo);
	char * ps = (char *)pseudostack;
	for (int i = 0x20; i < 4096; i+=0x28) {
		mem[i] ^= ps[i];
		if (mem[i] != 0) {
			printf("Oh honey, I'm sorry. Looks like your ticket has changed!\n");
			printf("You're now bound for:\n");
			printf("                                                                                                    \n");
			printf("      GGGGGGG      A     N   N  OOOOO   N   N 'SSSSS                                                \n");
			printf("      GG          A A    N N N  O   O   N N N  S                                                    \n");
			printf("      GG         AA AA   N N N  O   O   N N N  SSSSS                                                \n");
			printf("      GG   GG    A   A   N  NN  O   O   N  NN      S                                                \n");
			printf("      GGGGGGG    A   A   N   N  OOOOO   N   N  SSSSS                                                \n");
			printf("                                                                                                    \n");
			printf("             CCCCCCCCCCC       AAA     SSSSSSSSSS   TTTTTTTTTT   LLL           EEEEEEEEEEEE         \n");
			printf("             CCCCCCCCCC       A   A    SSSSSSSSSS   TTTTTTTTTT   LLL           EEE                  \n");
			printf("             CC              AA   AA   SS              TTT       LLL           EEE                  \n");
			printf("             CC              AAAAAAA   SSSSSSSSSS      TTT       LLL           EEEEEEEEEEEE         \n");
			printf("             CC              AA   AA           SS      TTT       LLL           EEE                  \n");
			printf("             CCCCCCCCCC      AA   AA           SS      TTT       LLLLLLLLLLL   EEE                  \n");
			printf("             CCCCCCCCCCC     AA   AA   SSSSSSSSSS      TTT       LLLLLLLLLLL   EEEEEEEEEEEE         \n");
			printf("                                                                                                    \n");
			printf("SS+K+SSS+++SSSSSS#+SS##S#SSSSSSSS####SK+KK++***+*K+K+++##@*+@@#+S##K*SKKKKKK*KKKK***K*K+SSSSSSK+#SS+\n");
			printf("###SSSSSSSSSSSS###SSS################SK****K+K*****+++KK++KS#S#KK@#@*+SK+KKKKK*+KK**KKK#SS#SS#K##SSS\n");
			printf("####SSSSS++SSS+###S#S##############@+K*****+SKK++KKKK+++++++KKK+*K++K+KKK+KSSSSSKK****S##S#S#SS##S#+\n");
			printf("@##SSSSSS+SSSSS###S###############S+**KK+SSS+S##++++++++S+++++KKK++KKK***K**S#SSSS**+S#######SS###SS\n");
			printf("##SSSSSSS+SSSSS###S#############SS+++++SSK***KKKK+++KK+KK+++++KK+K*++*KKK***+KSSSS**+S######SSS#@###\n");
			printf("#SSSSSSSS+SSSSS###S############SS**+++K+++S++*++++++++++++++KKKKK+++KK**++**K*+SSSK+SS+#####SS#S####\n");
			printf("#+#SSSSSSSSSSS###SS##########SSK+*+K+SSS+++K;:+KKKK+KKKK++++++++KKKKKKKKSS**KK+KSS*:SSSS####SSS#SS##\n");
			printf("#SS#SSSSSSSSSS###SS#########S+K++S++++K*****++SS+KKKK***KK***K+S+++++K*KKK+**K**KSK:SSSS##S###SSSS##\n");
			printf("#+##SSSSSSSSSS###S#S######S+++SS+++++++++++SSSS++K*KK**KK*++*KKKK*K+++++K**KK*K*+S+:KSSSS#S##SSSSS##\n");
			printf("#SSS####SSSSSS###S#S####S+KK+S++++++SSSS+KKK*+*++**++KKKK*+**+S+*::K++++++KKKKK***S+*+SSSS###SSSSS##\n");
			printf("+SSSSSS##SSS#S###S#S###+*KK+SSSSSS+S+++S++SSSSSSS++++K++K*K*;*+##K+:*++S+K*++K+K*++*++S#SS#SSS+SS+##\n");
			printf("KSSSSSSSSS#SSS###S###S**+++#@@@###############SSSS+++K+KKK+K+;;*+SSK++:*SSK++K*K++#+:+SS+SSSSSSSK+##\n");
			printf("+SS#SSSSSSSS#####S##SK*+S#@@@@@@@@@@@@@@@@##SS###SS+++++K+++K++*++*K+K+:;K++K****+SS;KSS+++SS++++K##\n");
			printf("SSS#SSSSSSSSS###SS##+*+##@@@@@@@@@@@@@@@@@@@#@###S+**KKK++++S+S#S+K**K+K***KKK+K+*#SK+SSSSSSS+S++K##\n");
			printf("SSSSSSSSSSSSS######SK+#@@@@@@@@@@@@@@@@@@@@@@###S+++**K++KSSSS+S##SSKK+SS#SK++++K;+++++SSSK+KKK*KSS#\n");
			printf("SSSSSSSSSSSSS###S#S++#@@@@@@@@@@@@@@@@@@@@@###S+**K***+*++*SS##S+SSS#SS+++S++++++++*+KK++KSS+SSS####\n");
			printf("SSSSSSSSSSSSS###S#++#@@@@@@@@@@@@@@@@@@@#####+*+;+*++**KKK*+#######@@@@#SK+++S++++SK+++**K#########@\n");
			printf("SSSSSSSSSSSSS###S+S#@@@@@@@@@@@@@@@@@@@#####+++;+KK*****K*K+S###@@@@@@@@@@#S++++++SS++++*+K########@\n");
			printf("SSSSSSSSSSSS####S+#@@@@@@@@@@@@@@@@@@@@####+++;+KKKKKKK*+K*++S###@@@@@@@@@@@@##SSS#SSKK+SK*S########\n");
			printf("SSSSSSSSSSSS###++S@@@@@@@@@@@@@@@@@@@@@####*+++*KKKKKKKK*K+*KKS###@@@@@@@@@@@@@@@@@@#SK++SK*S#######\n");
			printf("SSSSSSSSSSSS###+S@@@@@@@@@@@@@@@@@@@@@@###K;;;*KKKK*KKKKK*K+S*SS####@@@@@@@@@@@@@@@@@@SS+S++K#@@@@@@\n");
			printf("SSSSSSSSSSSS##++#@@@@@@@#+##@@@@@#@@@@@##S+;;+*KK**KKKKKKK+*K+KS#####@@@@@@@@@@@@@@@@@@#S++KKK#@@@#@\n");
			printf("SSSSSSSSSSSS##+#@@@@@@@#+K@#@@@@###+S@@##K;;+*KK***KKKKKKKKK*SKS#####@@@@@@@@@@@@@@@@@@@##++*;*S@@@@\n");
			printf("SSSSSSSSSSSS##S#@@@@@@S+;######S##++*S@##+;;+*K****KKKKKKKK+K+K+#####@@@@@@@@@@@@@@@@@@@@@#+K*:K@@##\n");
			printf("SSSSSSSSSSS##S#@#@@@@S;;+#@######*++*K##+;;;*KKKKKKKKKKKKKKKKK++#####@@@@@@@@@@@@@@@@@@@@@##++*+#@##\n");
			printf("S+SSSSSSSSS##S###@@@#;;;;+####SK+;++*KSS;;;*KKKKKKKKKKKKKKKK+K++S###@@@@@@@@@@@@@@@@@@@@@@@#+++**#@#\n");
			printf("SS+SSSSSSSS##S###@@@K;;;;+*KK*+++++*KK+;;;+K++++++++++KKKKKKKKKKS###@@@@@@@@@@@@@@@@@@@@@@@##*+K*S##\n");
			printf("SSSSSSSSSSS#S+##@@@#+;+++++++++****K+++:;**+S++++++++++KKKKKKKKK+##@@@@@@@#@@@@@@@@@@@@@@@@@#S:*K*K*\n");
			printf("SSSSSSSSS#S#S+##@#SS*+++******KKK+SSS*;;*K+SSSSSS+++++++KKKKKKK*+###@#+*####@@@@@@@@@@@@@@@@##*+*K*+\n");
			printf("SSSSSSSSS#S#++###++S+KKKKK++SS#S#SK*++;*++SSSSSSSSSSS+++KKK++KK**###+**+S###@@@@#@@@@@@@@@@@@#S*;**+\n");
			printf("SSSSSSSSSS##K+###+++++SSSSS++K*++++KK+*SSSSSSSSSSSSSSSS+K*K++K**;##S**++*####@@@#@##@@@@@@@@@@#+;+*+\n");
			printf("SSSSSSSSSS##KK##++++KKKKK*+**+**K++++KSSSSSS#SSSSSSSSSSSK**K+KKK:KS+K*++;+##S####@@*S@@@@@@@@@#S;;**\n");
			printf("SSSSSSS+SS##KK#++*++*KKKKK+++++++++*KSSSSS########S#SSSS+K**KKKK**#+KK*++++######@@**#@@@@@@@@#S++++\n");
			printf("SS#SSSSSSS##*K#K+;*+++++++++++++++**S#############SSSSSSS+***KKKK*S#+K*++++K####@@S++K@@@@@@@@@#+K++\n");
			printf("SSSK++S+###+*++;*+++S+++++++SSSSS**S################SS#SSSK***+++KK##S+K**++*+###S+++++@@@@@@@##S+;*\n");
			printf("SSS##S#S+#+*K*;KSSSSSSSSSSSSSSSS**S#####################SS+K*+K+++K*+##S+K*++++*++;+++*@@@@@@@###+;+\n");
			printf("S+S#####S+*+K++SSSSSSSSSSSSSSSSK++#######################SS+K**++++K**+#SS+K**++++++++++@@@@@@@##+;+\n");
			printf("S#######S**+*KSSSSSSSSSSSSSSSSS*+#########################SS+K+KS++++**KS##S+K***+++++*K@@@@##@##S+*\n");
			printf("S#######K*K*K+SSSSSSSSSSSSSSSS+KS##########################SS+*+SS++++K**+S##S+KK**++**K@@@@#####SKK\n");
			printf("S#S####+*K+*+SSSSSSSSSSSSSSSSSK+S###########################S++*KS++++++KK*K+##SS++KKK+SS#@@######*;\n");
			printf("SSSS##S*K;*K+SSSSSSSSSSSSSSSS++S###SSSSSSSS#################SS+K*SSSS+++++KK**+###SSSSSSS##@#####S+*\n");
			printf("######K**+K++SSSSSSSSSSSSSSSS+SS#SKK*KKKKKKK+++S#############SSS*KSSSSS++++++K*K+##S#####S#@######+*\n");
			printf("#####S*K+*++SSSSSSSSSSSSS#SSSSSSK++++**KKKKK***KK++SSSS#######SS+KSSSSSS+++++++K**+#SSSSSS######SSK+\n");
			printf("#####K**;K++SSSSSSSSSSSSS+KKK*+++KSSSSSSSSSS++++KKKK++SSS#####SSS+SSSSSSSSSS+S+++*+KSSSSSS######SSK+\n");
			printf("#####+K;*+++SSSSSSSSSSSS*;+*++*+S#############SS+++KKK++SS####SSSSSSSSSSSSSSS+S+++K+*#SSSSS#####S+++\n");
			printf("####++*+K+++SSSSSSSSSSS*++*+*S####@@@@####@@#####SS++K**K+S###SSSSSSSSSSSSSSSSSSS++K+*#SSSSS###SSK+S\n");
			printf("####+K**+++++SSSSSSSS+*+**+*S#@@@@@@@@@@@@@@@@@#####SS+K**KS#SSSSSSSSSSSSSSSSSSSSSS+K+K#SSS+###S+K+#\n");
			printf("###+;K*K+++++SSSSSSS+K***+K##@@@@@@@##@@##@@@@@@@@#####S+***+S#SSSSSSSSSSSSSSSSSSSSS+K+KS+SS###S+K+#\n");
			printf("###+;**KK+++SSSSSS++KKK*+K##@@@@@##+*K++K*KS####@@@@@@@##+K**KSSSSSSSSSSSSSSSSSSSSSSS+K+KSS+S#SS+*S#\n");
			printf("###,**+KK+++SSSSS++K*K**K##@@@@#KK+**KKK*KK+SK**+#@@@@@@##+K***KSSSSSSSSSSSSSSSSSSSSSS+K;++++#SS+*+S\n");
			printf("##+,*+*K++++SSSSS+KKKK**S#@@@@#K*+KKKK+KKKK++KKKK+++S@@@@##SK*KKK+++SSSSSSSSSSSSSSSSSS+++++KKSS+++SS\n");
			printf("##+:+;KKK++++SS+++KKK*++#@@@@S+KK++++SS+++++KKKK++K**S@@@@##+KKKKKKK+SSSSSSSSSSSSSSSSSS+K+K+KSSS*+++\n");
			printf("##;:;;KKK++++++++KKKK*K#@@@@S++++SS#######SSS++++KKKK+S#@@@@SKKK++K**+SSSSSSSSSSSSSSSS+++++++KSS+;+S\n");
			printf("#S;+;+KK++++++++KKKK**S#@@@#+SS################SS++KK++KS@@@#SKKK++K*KSSSSSSSSSSSSSSSSS++K;K;KSS*;++\n");
			printf("#++*;*KK+K+++++KKKKK**##@@@SS########@@@@@@@#####SS+++KKK#@@#S+KK+++KK+SSSSSSSSSSSSSSSSS+++*+++S*+K*\n");
			printf("SK*;:KKKKKK++++KKKK**S@@@@#######@@@@@@@@@@@@@@#####S+KK+S@@@#SKK++++K+SSSSSSSSSSSSSSSSS++*;*+++*+K*\n");
			printf("*++:+K+KKKK++KKKKK*++#@@@@###@@@@@@@@@@@@@@@@@@@#@###S+++S#@@#S+K+++++++SSSSSSSSSSSSSSSS++K;*+K+*+++\n");
			printf("*+;:*KKK*KKKKKKK***K##@@@@@@@@@@@@@@@@@@@@@@@@@@@@@####S+SS#@@S+K+++++++SSSSSSSSSSSSSSSSS+K+;+*+*K+*\n");
			printf("+*:;*KK**KKKKKKK***+#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@####SSS####++++++++++SSSSSSSSSSSSSSSS++*;+++*KK*\n");
			printf(";+;+KK***KK*KKK***+S#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@###SSS###+++++++++++SSSSSSSSSSSSSSS++*++++K+K*\n");
			printf("**+*KK+****KKK***KS#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@###S@##++++++++++SSSSSSSSSSSSSSSSS+K++++K+K*\n");
			printf("*+*K+*+****KK***KSS#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@###@@#+++++++++++SSSSSSSSSSSSSSSS+K*+;K*+KK\n");
			printf("+*KK+++***KKKKK+SSS#@@@@#++S+++S##SS@@@@@@@@@@@@@@@@@@@@@@@#@@#++++++++++++SSSSSSSSSSSSSSSS+*+;**K++\n");
			printf("KKK+K;++*KKK++SSSS##@@S++KK++KKKK+KKK+#@@@@@@@@@@@@@@@@@@@@@@@#S++++++++++SSSSSSSSSSSSSSSS++K+;K**+S\n");
			printf("KKKK*++*KKKKKK****++SK+S+++++KKK++++KKK+KKK+#@@@@@@@@@@@@@@@@@#S++++++++++SSSSSSSSSSSSSSSS++K+;KK*KS\n");
			printf("KKKK++*KKKK*+;;;;;**+;+*K++++KKK++KKKK++KKKK++++S@@@@@@@@@@@@@#S++++++++++SSSSSSSSSSSSSSSS++K+;*+**+\n");
			printf("KKKK+*KKKKK***KK+++++++K***+++++++KKKK++KKK+++KKK+S#@@@@@@@@@@#S++++++++++SSSSSSSSSSSSSSS+++K+;*KK*+\n");
			printf("*KK+;KKKKKKK*K+++++++SSSS+KK*KKK+SS+++S+KK++S++K+K+++S@@@@@@@@#S++++++++++++SSSSSSSSSSSSS+++K++K*KKK\n");
			printf("KKK++K++++KKK++++++++++SSSSS+KK**KKK+++S++++++KK++S+KK+#@@@@@@SS++++++++++++SSSSSSSSSSSSSS++K;;*+*KK\n");
			printf("KKK+;K++++K+++S+S++++++SSSSSSSSS+++K*****+SSSS++++S++++S##@@@@SSS++++++++++++SSSSSSSSSSSSS++*++*KK*K\n");
			printf("KK*++K++++K+++KKKKK+++++SSSSSSSSSSSSS+++KKK*K++K+SS+++SSSS#@@@SSS++++++++++++SSSSSSSSSSSS+++K*+KK++*\n");
			printf("KK*++++++++++K*KKK+***+++SSSSSSSSSSSSSSSSS++KKKKKKKKKKKKK+S@@SSSSS+++++++++++SSS++SSSSSS+++K***KK*K+\n");
			printf("K*K++K+++++*K+***+++++**K++SSSSSSSSSSSSSSSSSSSSSS+++++K*++++@SSSSS+++++++++++SSS++++SSSSS+++*+*KK+KK\n");
			printf("KKK++K++S+***+*K+*KKKK***++*K++SSSSSSSSSSSSSSSSSSSSSSSSS++K+++KSSSSS++++++++++SS+++++SS+++K+*+*K+++K\n");
			printf("*K+*+K+S+*+***K**K++KK*+++++++++*K+SSSSSSSSSSSSSSSSS+S++++++K+++K+SSSSS++++++++++++++SS+++KKK*KKK+*+\n");
			printf("*+SK+K++*++K*+KKK++++KKK*K+*++++++;;+*K++SSSSSSSSS+S++++++++++K*K*K+SSS++++++++++++++SSS+++*K*K+KKK+\n");
			printf("+S+K*K+*++**K++++SS++SS+++KKK+***+++++++**KK++S++++++++++++++SS+++KKK++++++++++++++++SS+++KK***SS*K*\n");
			printf("Si++K+*K+KKK*KS+SSSS++SS++S+S+KKKKK*KK*++++++++****KKK+++++SSSSSS++++K++++++++++++++++SS+++K+K**+SS+\n");
			printf("Game over!\n");
			exit(1);
		}
	}
	printf("                         ____\n");
	printf("                   *  _.'    ##..--.\n");
	printf("         *         .-'   __ ##  .   \\     _.----._\n");
	printf("                  /   _  '.'.'|' -'\\|    | AUGH!! |\n");
	printf("             *   /_.'' ''.#'//   ą .      Ż'----'Ż\n");
	printf("                        /''|/  .__'\n");
	printf("                       \\-'Ż\\   /\n");
	printf("                 .---|Ż'----___.-\n");
	printf("                \\   .    .'\\    |__\n");
	printf("                 \\_ |  .'.. \\  '|.     __..'''Ż\n");
	printf("                   '| '--..__\\  |.\\..'''\n");
	printf("                   .   --  __  .__'\\+\n");
	printf("                   |  'ŻŻ  --. |   '\n");
	printf("                   |  \\__ __.  |'/\n");
	printf("   .-..._   __    /'. '._O_.'.'_/ '.\n");
	printf("  /      Ż/  /-.__/Ż'''.._..'_/     '.\n");
	printf(" /  ^~DLF | |    '     .'      ..     \\\n");
	printf("|  .\\...__ \\.       .'          '.  ' \\\n");
	printf("|.'       Ż Ż '-.__.'              \\ ..''\\\n");
	printf("                                    \\___.'\n");
	printf("                                     |    \\\n");
	printf("                                     \\     \\\n");
	printf("                                      \\   .'...\n");
	printf("                                       |     _.'\n");
	printf("                                        \\.''Ż\n");
	printf("Congratulations! You missed the train, but you were able to run all the way there and get the flag!\n");

	fclose(fp);
	free_tree(root);
	free(pseudostack);
	free(mem);
}
