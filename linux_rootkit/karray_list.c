/*
 * Author: Daniel Liscinsky
 */



#include <linux/slab.h>

#include <linux/types.h>



typedef struct karraylist {
	unsigned int length; // The number of elements currently in the list
	unsigned int capacity; // The maximum length of the list (based of currently allocated memory) at which the list needs to be reallocated
	void *elements;
	size_t element_size; // The size of the element type, in bytes
} karraylist_t;



/**
 * 
 * 
 * @param list		A pointer to the newly allcated list is returned in this parameter.
 * 
 * @return 
 */
int new_karraylist(karraylist_t **list, size_t element_size, unsigned initial_capacity = 32) {
	
	// Allocate kernel memory for a karraylist struct
	karraylist_t *newlist = kmalloc(sizeof(karraylist_t), GFP_KERNEL);

	if (!newlist) {
		return -ENOMEM;
	}

	// Allocate kernel memory for a karraylist struct
	newlist->elements = kmalloc(element_size * initial_capacity, GFP_KERNEL);
	if (!newlist->elements) {
		kfree(newlist);
		return -ENOMEM;
	}

	ksize(newlist->elements)
	
	newlist->length = 0;
	newlist->capacity = initial_capacity;
	newlist->element_size = element_szie;

	*list = newlist;
	return 0;
}

void initWithSize(ArrayList *const list, int size)
{
	initWithSizeAndIncRate(list, size, 50);
}

void init(ArrayList *const list)
{
	initWithSize(list, 100);
}

/*
void arraryCopy(void *dest, int dIndex, const void* src, int sIndex, int len, int destLen, size_t size)
{
	uint8_t *udest = (uint8_t*)dest;
	uint8_t *usrc = (uint8_t*)src;
	dIndex *= size;
	sIndex *= size;
	len *= size;
	destLen *= size;

	if (src != dest)
	{
		memcpy(&udest[dIndex], &usrc[sIndex], len);
	}
	else
	{
		if (dIndex > sIndex)
		{
			uint8_t *tmp = (uint8_t*)ExAllocatePoolWithTag(NonPagedPool, size, 'F');
			memcpy(tmp, &udest[dIndex], (destLen - dIndex));
			memcpy(&udest[dIndex], &usrc[sIndex], len);
			memcpy(&udest[dIndex + len], tmp, (destLen - dIndex));
			ExFreePoolWithTag(tmp, 'F');
		}
		else if (sIndex > dIndex)
		{
			memcpy(&udest[dIndex], &usrc[sIndex], (destLen - sIndex) + 1);
		}
		else
			return;
	}
}
*/

void clear(ArrayList *const list) {
	
	while (list->current >= 0) {
		FreeUString(list->elements[list->current].data);
		list->current--;
	}
}

void wide(ArrayList* const list)
{
	list->size += list->increment_rate;
	Element *newArr = (Element*)ExAllocatePoolWithTag(NonPagedPool, sizeof(Element), 'T');
	arraryCopy(newArr, 0, list->elements, 0, list->current, list->size, sizeof(Element));
	//ExFreePoolWithTag(list->elements, 'Foo');
	list->elements = newArr;
}

int add(ArrayList *const list, Element *e)
{
	UNICODE_STRING *dest = { NULL };
	NTSTATUS status = STATUS_SUCCESS;

	if (++list->current < list->size)
	{
		status = RtlDuplicateUnicodeString(1, e->data, dest);
		DbgPrint("RtlDuplicateUnicodeString() status: 0x%x", status);

		list->elements[list->current].data = dest;
		return 1;
	}
	else
	{
		wide(list);
		status = RtlDuplicateUnicodeString(1, e->data, dest);
		DbgPrint("RtlDuplicateUnicodeString() status: 0x%x", status);
		list->elements[list->current].data = dest;
		return 1;
	}
	return 0;
}

int indexOf(const ArrayList *const list, Element *e)
{
	int index = 0;
	while (index <= list->current)
	{
		if (e->data->Length == list->elements[index].data->Length &&
			0 == wcsncmp(e->data->Buffer,
				list->elements[index].data->Buffer,
				list->elements[index].data->Length))
			return index;
		index++;
	}
	return 0;
}

void clean(ArrayList *list)
{
	ExFreePoolWithTag(list->elements, 'Fo');
}

ArrayList list;
Element e;



