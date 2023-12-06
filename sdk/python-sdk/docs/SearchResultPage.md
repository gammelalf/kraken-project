# SearchResultPage

Response containing paginated data

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**items** | [**List[SearchResultEntry]**](SearchResultEntry.md) | The page&#39;s items | 
**limit** | **int** | The limit this page was retrieved with | 
**offset** | **int** | The offset this page was retrieved with | 
**total** | **int** | The total number of items this page is a subset of | 

## Example

```python
from kraken_sdk.models.search_result_page import SearchResultPage

# TODO update the JSON string below
json = "{}"
# create an instance of SearchResultPage from a JSON string
search_result_page_instance = SearchResultPage.from_json(json)
# print the JSON string representation of the object
print SearchResultPage.to_json()

# convert the object into a dict
search_result_page_dict = search_result_page_instance.to_dict()
# create an instance of SearchResultPage from a dict
search_result_page_form_dict = search_result_page.from_dict(search_result_page_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

