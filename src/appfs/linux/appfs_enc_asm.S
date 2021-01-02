
	.section .rodata.appfs

	.align 4
	.global appfs_tar_start

appfs_tar_start: 
	.incbin "appfs.tar.enc"

	.align 4
	.global appfs_tar_end

appfs_tar_end:

	.section .note.GNU-stack,"",%progbits

