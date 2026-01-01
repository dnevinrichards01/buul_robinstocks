
# Welcome to the Django Robinhood Integration for Buul
*(Visit [Buul's backend repo](https://github.com/dnevinrichards01/buul_backend/tree/try_it_out_local) for more info on Buul and a tutorial)*

### About

This is a Django 'app' based off of the open source [`robinstocks`](https://github.com/jmfernandes/robin_stocks) library to connect with the Robinhood brokerage's private API. 

#### Key Tools Used:
1. Django, Django Rest Framework
2. Postman

#### Key Features:
1. Automatic refreshing of access tokens
2. Endpoint to allow [Buul's frontend](https://github.com/dnevinrichards01/buul_app) to sign into Robinhood with 2-factor verification
3. Get account and balance information, deposit, and invest
4. Envelope encryption of sensitive fields including keys upon each database access


#### Some Files / Landmarks of Interest:
##### 1. Authentication / sign-in process and refreshing
- **`robin_stocks/robinhood/authentication.py`** is the most important file
- `robin_stocks/serializers.py`
- `robin_stocks/tasks.py`
##### 2. Invest
- function `order` in `robin_stocks/robinhood/orders.py`
- function `deposit_funds_to_robinhood_account` in `robin_stocks/robinhood/accounts.py`
##### 3. Envelope encryption and data modeling
- `robin_stocks/models.py`
- In the [`buul_backend`](https://github.com/dnevinrichards01/buul_backend/tree/feature_projections_graph) repo's `buul_backend/encryption.py`

