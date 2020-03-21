# punch cards in program order 0-8
cat code.cobc | python3 punch.py

# shuffle cards - after shuffle:
#   program order =  9, 2, 3, 4, 6, 1, 5, 7, 8 
#   original idx  =  0  1  2  3  4  5  6  7  8
mv img0.jpg img9.jpg    
mv img2.jpg tmp.jpg
mv img1.jpg img2.jpg
mv img5.jpg img1.jpg
mv img6.jpg img5.jpg
mv img4.jpg img6.jpg
mv img3.jpg img4.jpg
mv tmp.jpg  img3.jpg
