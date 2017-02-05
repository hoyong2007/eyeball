from threading import *
import time

lock = Lock()

class testing (Thread):
	def __init__(self,num):
		Thread.__init__(self)
		self.num = num
	def run(self):
		for _ in range(20):
			lock.acquire()
			print self.num
			lock.release()
			time.sleep(0.1)


def onetwo():
	time.sleep(0.1)
	for _ in range(10):
		time.sleep(0.1)
		print "onwtwo !!"

for num in ["one","two","three"]:
	test = testing(num)
	test.start()

t1 = Thread(target=onetwo)
t1.start()
