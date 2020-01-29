/**
 * All functions you make for the assignment must be implemented in this file.
 * Do not submit your assignment with a main function in this file.
 * If you submit with a main function in this file, you will get a zero.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "debug.h"
#include "sfmm.h"

#define MIN_BLOCK_SIZE 32

//helper functions
int get_free_list(int size);
int validate_pointer(void *p);
void remove_node_from_list(sf_block *p);
int extend_heap();
void print_bits(size_t const size, void const * const ptr); 

/*
 * sf_malloc
 *
 *  For learning purposes. If its the first call, sf_malloc initializes a chunk of memory,
 *  the freelists, and allocates space. Avoids fragmentation by preventing block splintering
 *
 *  args:
 *      size_t size: size of the block to be allocated
 *  return:
 *      pointer to the adddress of the allocated space (payload)
 */
void *sf_malloc(size_t size) {
    //determine if request size 0
    if(size <= 0){
        return NULL;
    }

    //IF ITS THE FIRST CALL OF MALLOC INITIALIZE THE HEAP
    if(sf_mem_start() == sf_mem_end()){
        //add a new page to heap
        sf_mem_grow();
        if(sf_errno == ENOMEM){
            return NULL;
        }
        //its the first call so lets initialize pro/epi
        debug("[Initializing heap]...");

        //add prologue
        sf_prologue *prolog = (struct sf_prologue *) sf_mem_start();
        prolog->header = (MIN_BLOCK_SIZE | 0x03) ;
        prolog->footer = prolog->header ^ sf_magic();

        //add epilogue
        sf_epilogue *epilog = (struct sf_epilogue *) sf_mem_end();
        epilog = epilog-1;
        epilog->header = 0 | 0x02; //epilog header block size is 0 (see doc)//bits: alloc = 1, prv alloc = 0

        debug("[Prologue and epilogue initialized]");
        debug("[Initializing empty free lists]...");

        //initialize freelists
        for(int i = 0; i < NUM_FREE_LISTS; i++){
            //add head for each list
            sf_block sntl;
            sntl.body.links.next = &sf_free_list_heads[i];
            sntl.body.links.prev = &sf_free_list_heads[i];

            sf_free_list_heads[i] = sntl;
        }

        debug("[Free lists initialized]");
        debug("[Adding first block]...");

        //Now add the newly created block of memory to the freelist

        //get the address to write to (right after prolog footer)
        char *addr = (char *) prolog; //address of prologue
        addr = addr + MIN_BLOCK_SIZE;
        //place free block right after prologue
        sf_block *first_free_block = (struct sf_block *) addr;
        first_free_block->header = (4048 | 0x01);
        //add to the 8th list
        first_free_block->body.links.next = &sf_free_list_heads[7];
        first_free_block->body.links.prev = &sf_free_list_heads[7];
        sf_free_list_heads[7].body.links.next = first_free_block;
        sf_free_list_heads[7].body.links.prev = first_free_block;

        //add footer of the block of memory
        addr = (char *) sf_mem_end();
        addr = addr - 16;
        sf_block *first_free_block_footer = (struct sf_block *) addr;
        first_free_block_footer->prev_footer = first_free_block->header ^ sf_magic();

        debug("[Created first free block]");
    } else {
        debug("[Note: Not first malloc call]");
    }
    printf("\n");

    debug("[Adding block of memory]...\n");
    //determine the size of the block to be allocated
    //add header size + padding. must be multiple of 16 for alignment
    int blksize = (int) size;
    blksize += 16; //add bytes for header and footer
    //debug("SIZE IS:%d", blksize);

    //round up to multiple of 16
    blksize = blksize + 16 - 1 - (blksize -1) % 16;
    //debug("PADDED SIZE IS:%d", blksize);

    //search free list from begining until large enough block is found to place it in
    for (int i = 0; ; i++){
        //if we found no block (we're at the end of the free lists) grow a page
        if(i >= NUM_FREE_LISTS){
            debug("[EXTENDING HEAP]");
            int err = extend_heap();
            if(err != 0){
                return NULL;
            }
            i = 0;
            continue;
        }
        //if the curr list is empty, go to next list
        if(sf_free_list_heads[i].body.links.next == &sf_free_list_heads[i]){
            continue;//increment i and go to next head
        }

        //debug("Found a potential list. list:%d", i);
        //search for a block in this list
        sf_block *cnode = &sf_free_list_heads[i];
        while(true){
            cnode = cnode->body.links.next; //get the next block in list

            //does it fit?
            int freeblcksize = cnode->header & BLOCK_SIZE_MASK;
            if(blksize <= freeblcksize){

                //will it splinter?
                if((freeblcksize - blksize < MIN_BLOCK_SIZE) && (freeblcksize-blksize != 0) ){
                    debug("[Block will splinter]:remaining %d", freeblcksize-blksize);
                    continue; //we wont be placing it here
                }

                //place the block
                debug("[Placing the block]...");

                //remove old freeblock from its freelist
                remove_node_from_list(cnode);

                //set the size of the new free block
                freeblcksize = freeblcksize - blksize;

                //check if previous block is alloc
                int prevalloced = (cnode->prev_footer ^ sf_magic()) & 0x03; //contains value of last two bits
                prevalloced = prevalloced >> 1;//prev_footer alloc bit
                //set the header
                cnode->header = blksize | prevalloced | 0x02;//set the alloc bits

                //if the freeblock is zero, we're just removing it
                if(freeblcksize != 0){
                    debug("[Moving the free block]...");
                    //move the freeblock and link it up
                    char *tmp_addr = (char *)cnode + blksize;
                    sf_block *newfree = (struct sf_block *) tmp_addr;

                    //set the header
                    newfree->header = freeblcksize | 0x01;
                    debug("[New free block at]: %p, Free block size before/after split: %d/%d, Alloc'd block size: %d", newfree, freeblcksize + blksize,freeblcksize, blksize);
                    newfree->prev_footer = cnode->header ^ sf_magic();

                    //add the new freeblock footer
                    tmp_addr = tmp_addr + (newfree->header & BLOCK_SIZE_MASK);
                    sf_block *newfreefoot = (struct sf_block *) tmp_addr;
                    newfreefoot->prev_footer = newfree->header ^ sf_magic();

                    debug("[Updating list references]...");
                    int flindex = get_free_list(freeblcksize);
                    //debug("Blck list = %d", flindex);

                    newfree->body.links.next = sf_free_list_heads[flindex].body.links.next;
                    sf_free_list_heads[flindex].body.links.next = newfree;
                    // link newfree node prev to head
                    newfree->body.links.prev = &sf_free_list_heads[flindex];
                } else {
                    //we just set the footer of the block
                    char *tmp_addr = (char *)cnode + blksize;
                    sf_block *next = (struct sf_block *) tmp_addr;
                    next->prev_footer = cnode->header ^ sf_magic();
                }

                //return the payload, pad by 16 bytes
                char *pad = (char *) cnode;
                pad = pad + 16;
                void * ret = pad;
                debug("[MALLOC RETURNING POINTER:%p]", pad);
                return ret;
            }
            //check if we're back at the start of the list
            if(cnode->body.links.next == &sf_free_list_heads[i]){
                debug("[Doesn't fit in any freeblocks in list]");
                break;
            }
        }
    }

}

/*
 * sf_free
 *
 *  For learning purposes. sf_free attempts to free the memory at a given pointer.
 *  When freeing a block of memory, adjacent blocks are checked to see if they are
 *  also free. If they are free, the blocks are coalesced and added to the appropriate
 *  freelist. 
 *
 *  args:
 *      void* pp: address of the block of memory to free
 *  return:
 *      nothing
 */
void sf_free(void *pp) {
    debug("[Freeing pointer]: %p", pp);
    //verify the pointer is valid
    char *pointer = (char *) pp;
    pointer -=16;
    int valid_p = validate_pointer(pointer);

    //abort if invalid pointer
    if(!valid_p)
        abort();

    sf_block *freethisblk = (struct sf_block *) pointer;
    int freethisblk_size = freethisblk->header & BLOCK_SIZE_MASK;

    //get prev block size
    int prevblk_size = (freethisblk->prev_footer ^ sf_magic()) & BLOCK_SIZE_MASK;
    char *tmp_addr = (char *) freethisblk;
    tmp_addr = tmp_addr - prevblk_size;
    sf_block *prevblk = (struct sf_block *) tmp_addr;

    //get next block size
    tmp_addr = (char *) freethisblk;
    tmp_addr = tmp_addr + (freethisblk->header & BLOCK_SIZE_MASK);//go to next block
    sf_block *nextblk = (struct sf_block *) tmp_addr;
    int nextblk_size = nextblk->header & BLOCK_SIZE_MASK;

    //now, calculate the size of the new free block
    sf_block *newfreeblk = freethisblk;
    int newfreeblk_size = freethisblk_size;
    int prevalloc = 0;

    //check prv alloc bit of block we're freeing
    if((freethisblk->header & 0x01) == 0){
        //we are going to coalesce with prev block
        newfreeblk_size += prevblk_size;//add increase size
        newfreeblk = prevblk;//block gets replaced

        //remove it from the list
        remove_node_from_list(prevblk);
    }
    //for setting the prevalloc bit
    prevalloc = newfreeblk->header & 0x01;//get the prev alloc bit
    //check the next block alloc bit
    if((nextblk->header & 0x2) == 0){
        //we are goign to coalesce with next block
        newfreeblk_size += nextblk_size;

        //remove it from the list
        remove_node_from_list(nextblk);

        //set the footer
        tmp_addr = (char *) nextblk;
        tmp_addr = tmp_addr + (nextblk_size);
        sf_block *nextnext = (struct sf_block *) tmp_addr;
        nextnext->prev_footer = (newfreeblk_size | prevalloc) ^ sf_magic();// size and prevalloc set
        nextnext->header= nextnext->header ^ 0x01;//flip it to unalloc
    } else {
        //we are not going to coalesce with next block
        //set the footer by going to next block
        nextblk->prev_footer = (newfreeblk_size | prevalloc) ^ sf_magic();// size and prevalloc set
        nextblk->header= nextblk->header ^ 0x01;//flip it to unalloc
    }
    //set the header
    newfreeblk->header = (newfreeblk_size | prevalloc);

    //put the new free block in a list
    //determine the size class appropriate for the block
    int flindex = get_free_list(newfreeblk_size);
    newfreeblk->body.links.next = sf_free_list_heads[flindex].body.links.next;
    sf_free_list_heads[flindex].body.links.next = newfreeblk;
    // link node prev to head
    newfreeblk->body.links.prev = &sf_free_list_heads[flindex];

    sf_free_list_heads[flindex].body.links.next = newfreeblk;
    return;
}

/*
 * sf_realloc
 *
 *  For learning purposes. sf_free attempts to reallocate the memory at a given pointer.
 *  Reallocating to larger size simply calls malloc to create the new size and copy the
 *  payload data. Reallocating to smaller size requires checks to ensure there will be no
 *  block splintering. Padding is added if necessary to satisfy block alignment.
 *
 *  args:
 *      void* pp: address of the block of memory to free
 *      size_t rsize: size to reallocate to
 *  return:
 *      pointer to the reallocated block of memory
 */
void *sf_realloc(void *pp, size_t rsize) {
    //validation
    //first verify that pointer and size parameters are valid
    char *pointer = (char *) pp;
    pointer -=16;
    int valid_p = validate_pointer(pointer);

    //abort if invalid pointer
    if(!valid_p)
        abort();
    //if pointer is valid but size is 0, free the block and return null
    if(valid_p && rsize <= 0){
        //free the block and return null
        sf_free(pp);
        return NULL;
    }

    //validation done
    //check the size of the block
    char *tmp_addr = (char *) pp;
    tmp_addr -= 16;
    sf_block *oldblock = (struct sf_block *) tmp_addr;
    int old_size = (oldblock->header & BLOCK_SIZE_MASK)-16;//remove header+footer from size
    debug("old payload size: %d, new payload size: %ld\n\n", old_size, rsize);

    //realloc to larger size
    if(old_size < rsize){
        debug("[ALLOCATING TO LARGER SIZE]...");
        void *new_alloc = sf_malloc(rsize);
        if(new_alloc == NULL){
            return NULL;
        }
        //calculate number of bytes to copy
        debug("[COPYING :%d: bytes]", old_size);
        //copy only the payload
        char *old_payload = (char *)oldblock;
        old_payload +=16;
        memcpy(new_alloc, old_payload, old_size);
        sf_free(pp);
        return new_alloc;
    }
    //realloc to smaller size
    else if(old_size > rsize){
        debug("[ALLOCATING TO SMALLER SIZE]");
        //size of the payloads + paddings
        old_size += 16;//already aligned
        rsize += 16;
        //lets align rsize
        rsize = rsize + 16 - 1 - (rsize - 1) % 16;
        //int free_block_size = old_size-rsize;
        debug("old_size w/ padding: %d, rsize w/padding:%d", old_size, (int)rsize);
        debug("free block will be size: %d w/padding", old_size-(int)rsize);
        debug("remalloced block will be: %d w/padding\n", (int)rsize);

        //will block splinter?
        if((old_size - rsize) < MIN_BLOCK_SIZE){
            //it will splinter
            debug("smaller size will cause splinter");
            //just return it
            return pp;
        } else {
            debug("smaller size will not cause splinter");
            //we will split the block.
            //add a new alloc'd block in its place then call sf_free()
            tmp_addr = (char *) oldblock;
            tmp_addr = tmp_addr + (oldblock->header & BLOCK_SIZE_MASK);
            sf_block *old_next_block = (struct sf_block *) tmp_addr;//get the next block in memory
            debug("old_next_block: %p", old_next_block);

            tmp_addr = (char *) oldblock;
            tmp_addr = tmp_addr + rsize;
            //new block we're gonna free
            sf_block *free_block = (struct sf_block *) tmp_addr;

            int prevalloc = oldblock->header & 0x01;
            //update the old block header
            oldblock->header = ((int)rsize) | prevalloc | 0x02;
            //update the old block footer
            free_block->prev_footer = oldblock->header ^ sf_magic();
            debug("adress of oldblock footer:%p", &free_block->prev_footer);
            debug("oldblock size from footer:%ld", (free_block->prev_footer ^ sf_magic() ) & BLOCK_SIZE_MASK);

            //update the free block header
            debug("new block header is :%d", ((int)rsize));
            free_block->header = (old_size -(int)rsize) | 0x03;
            //update the free block footer
            old_next_block->prev_footer = free_block->header ^ sf_magic();

            //now free the new block
            char *new_block_payload = (char *) free_block;
            new_block_payload +=16;
            sf_show_heap();
            sf_free(new_block_payload);

            //return pointer to the old block (realloc'd)
            return pp;
        }
    }
    else {
        //blocks are the same size, no need to realloc
        debug("[Block sizes are the same]");
        return pp;
    }
}


/*
 * get_free_list
 *
 *  Get the appropriate freelist for a free block of a given size
 *
 *  args:
 *      int size: size of the free block
 *  return:
 *      the index of the appropriate freelist
 */
int get_free_list(int size){
    debug("FINDING FREE LIST SIZE:%d", size);
    if(size <= MIN_BLOCK_SIZE){
        return 0;
    } else if(size <= MIN_BLOCK_SIZE * 2){
        return 1;
    } else if(size <= MIN_BLOCK_SIZE * 4){
        return 2;
    } else if(size <= MIN_BLOCK_SIZE * 8){
        return 3;
    } else if(size <= MIN_BLOCK_SIZE * 16){
        return 4;
    } else if(size <= MIN_BLOCK_SIZE * 32){
        return 5;
    } else if(size <= MIN_BLOCK_SIZE * 64){
        return 6;
    } else if(size <= MIN_BLOCK_SIZE * 128){
        return 7;
    } else { //else greater than 128 * M
        return 8;
    }
}

/*
 * validate_pointer
 *
 *  Checks if a pointer is valid
 *
 *  args:
 *      void *p: the pointer to check
 *  return:
 *      0: if invalid pointer
 *      1: if valid pointer
 */
int validate_pointer(void *p){
    //check if null pointer
    if(!p){
        debug("[invalid pointer] pointer is null");
        return 0;
    }

    sf_block *bp = (struct sf_block *) p;
    //check allocated bit in the header is 0
    if((bp->header & 0x02) == 0x0){
        debug("[invalid pointer] Cannot free unallocated block: %lu", bp->header);
        return 0;
    }
    //check the header of the block is before the end of the prologue,
    //      or the footer of the block is after the beginning fo the epilogue
    sf_prologue *prolog = (struct sf_prologue *) sf_mem_start();
    sf_epilogue *epilog = (struct sf_epilogue *) sf_mem_end();

    int prologsize = (prolog->header & BLOCK_SIZE_MASK);
    if ((void *) p < ((void *) prolog) + prologsize){//TODO make sure this arithmetic is good
        debug("[invalid pointer] points before prolog");
        return 0;
    }
    if ((void *) p > (void *) epilog){
        debug("[invalid pointer] points after epilog: %p", p);
        return 0;
    }

    //check the block_size field is less than min block size 32bytes
    if (prologsize < MIN_BLOCK_SIZE){
        debug("[invalid pointer] block size field <32");
        return 0;
    }

    //check the prev_alloc field is 0, indicating that prev plock is free but alloc field of prev block header is not 0
    sf_block *block_to_free = (struct sf_block *) p;
    if((block_to_free->header & 0x01) == 0x0){
        debug("[invalid pointer] prev alloc free");
        return 0;
    }

    //check bitwise XOR of the footer contents and the value returned  by sf_magic() does not equal the header contents
    //if any fail, calling function will abort and exit the fuction.
    char * addr = (char *) block_to_free;
    addr = addr + (block_to_free->header & BLOCK_SIZE_MASK);
    sf_block *next_block = (struct sf_block *) addr;
    if(block_to_free->header != (next_block->prev_footer ^ sf_magic())){
        debug("[invalid pointer] magic footer not matching");
        return 0;
    }

    return 1;
}


/*
 * extend_heap
 *
 *  Adds a new page of memory to the heap. The chunk of memory used by this program
 *  is wrapped by a "header" prologue and "footer" epilogue. When adding a new page
 *  of memory, the epilogue must be placed at the end of the boundary.
 *
 *  args:
 *  return:
 *      0: if successful
 *      nonzero: if unsuccessful
 */
int extend_heap(){
    //get the original epilog
    sf_epilogue *oldepilog = (struct sf_epilogue *)sf_mem_end();
    oldepilog = oldepilog-1;

    //get the block of the epilog
    sf_block *newfreeblock = (struct sf_block *) (oldepilog-1);
    char *tmp_addr = (char *) newfreeblock;
    tmp_addr = tmp_addr - ((newfreeblock->prev_footer ^sf_magic()) & BLOCK_SIZE_MASK);
    //lastblock contains last free or alloc'd block in memory
    sf_block *lastblock = (struct sf_block *) tmp_addr;

    //if sf_mem_grow() returns null, and sf_errno is enomem, we're gonna cancel malloc call
    sf_mem_grow();
    if(sf_errno == ENOMEM){
        return -1;
    }

    //get the new epilog
    sf_epilogue *newepilog = (struct sf_epilogue *) sf_mem_end();
    newepilog = newepilog-1;
    //set the new epilog
    newepilog->header = oldepilog->header;


    //now there are two cases, block before the epilog is free OR allocated
    //if its allocated, we just have to add a new free block
    //if its not allocated, we have to coalesce then add the block

    //not allocated, coalesce
    if((lastblock->header & 0x2) == 0){
        //remove old freeblock from its freelist
        remove_node_from_list(lastblock);

        //get prev block size
        int lastblock_size = lastblock->header & BLOCK_SIZE_MASK;

        int newfreeblock_size = lastblock_size + 4096;//add one page of memory
        int prevalloc = lastblock->header & 0x01; //get the prev alloc bit
        newfreeblock = lastblock;//block gets replaced
        newfreeblock->header = newfreeblock_size | prevalloc;//set the prev alloc bit and size

        //set the footer
        sf_block *footerblock = (struct sf_block *) (newepilog-1);
        footerblock->prev_footer = newfreeblock->header ^ sf_magic();

        //insert into appropriate freelist
        int flindex = get_free_list(newfreeblock_size);
        newfreeblock->body.links.next = &sf_free_list_heads[flindex];
        newfreeblock->body.links.prev = &sf_free_list_heads[flindex];
        sf_free_list_heads[flindex].body.links.next = newfreeblock;
        sf_free_list_heads[flindex].body.links.prev = newfreeblock;

    }
    //its allocated, just place new free block
    else {
        newfreeblock->header = (4096 | 0x01);//todo set the alloc bits properly
        //add to the 8th list
        newfreeblock->body.links.next = &sf_free_list_heads[8];
        newfreeblock->body.links.prev = &sf_free_list_heads[8];
        sf_free_list_heads[8].body.links.next = newfreeblock;
        sf_free_list_heads[8].body.links.prev = newfreeblock;

        //add footer of the block of memory
        tmp_addr = (char *) sf_mem_end();
        tmp_addr = tmp_addr - 16;
        sf_block *new_free_block_footer = (struct sf_block *) tmp_addr;
        new_free_block_footer->prev_footer = newfreeblock->header ^ sf_magic();
    }

    return 0;
}

/*
 * remove_node_from_list
 *
 *  Helper function
 *  Removes a given block from the freelist.
 *
 */
void remove_node_from_list(sf_block *p){
    //set the links in the list
    p->body.links.next->body.links.prev = p->body.links.prev;
    p->body.links.prev->body.links.next = p->body.links.next;
}
/*
 * print_bits
 *
 *  Helper function
 *  Prints the bits of a given address in memory. Assumes little endian machine.
 *
 */
void print_bits(size_t const size, void const * const ptr)
{
    unsigned char *b = (unsigned char*) ptr;
    unsigned char byte;
    int i, j;

    for (i=size-1;i>=0;i--)
    {
        for (j=7;j>=0;j--)
        {
            byte = (b[i] >> j) & 1;
            printf("%u", byte);
        }
    }
    puts("");
}