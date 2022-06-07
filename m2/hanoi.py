#!/usr/bin/env python3
A = ['a', 4, 3, 2, 1]
B = ['b']
C = ['c']

def move(n, source, target, auxiliary, src, tgt, aux):
    if n > 0:
        # move n - 1 disks from source to auxiliary, so they are out of the way
        move(n - 1, source, auxiliary, target, src, aux, tgt)

        # move the nth disk from source to target
        print('move from '+str(src)+' to '+str(tgt))
        target.append(source.pop())

        # Display our progress
        print(A)
        print(B)
        print(C)
        print('##############')

        # move the n - 1 disks that we left on auxiliary onto target
        move(n - 1, auxiliary, target, source, aux, tgt, src)

# initiate call from source A to target C with auxiliary B
move(4, A, C, B, A[0], C[0], B[0])
