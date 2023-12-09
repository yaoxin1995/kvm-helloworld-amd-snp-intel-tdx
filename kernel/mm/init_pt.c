/*use extern to reference all global variables you will use here*/
/*this function should create pagetables for a given size of memory*/
/*it is possible to also parse the hob here and store the information in
 * static structure defined in this file
 * once initialization is done, the enablemennt of cr3 will be done in the 
 * _start routine
 */
 
 /*assume you know the base address of RAM (region you want to use)
  * assume you know the base virtual address you want to use
  * assume you know the size of ram
  * This function can also take arguments from hob and use it to make decision above.
  */
void init_kernel_page_tables()
{
}
