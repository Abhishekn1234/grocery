import React, { useState, useEffect } from 'react';
import { Table, Button } from 'react-bootstrap';
import axios from 'axios';

const Orders = () => {
  const [orders, setOrders] = useState([]);

  useEffect(() => {
    fetchOrders();
  }, []);

  const fetchOrders = async () => {
    try {
      const response = await axios.get('http://localhost:5000/orders');
      const ordersData = response.data;
      setOrders(ordersData);
    } catch (error) {
      console.error('Error fetching orders:', error);
    }
  };

  // Calculate total price for each product
  const calculateProductTotal = (product) => {
    const quantity = parseFloat(product.quantity);
    const price = parseFloat(product.price);
    if (isNaN(quantity) || isNaN(price)) {
      return 0; // Return 0 if either quantity or price is not a valid number
    }
    return quantity * price;
  };

  // Calculate total price for all products in the order
  const calculateTotalPrice = () => {
    let totalPrice = 0;
    orders.forEach((order) => {
      order.products.forEach((product) => {
        totalPrice += calculateProductTotal(product);
      });
    });
    return totalPrice;
  };

  // Function to handle payment
  const handlePayment = () => {
    // Perform payment processing here based on the total price
    console.log('Initiating payment process...');
    console.log('Total Price:', calculateTotalPrice().toFixed(2));
    // You can integrate your payment gateway logic here
  };

  return (
    <div style={{ backgroundColor: 'orange', minHeight: '100vh', color: '#fff' }}>
      <h2>Orders</h2>
      {orders.length === 0 ? (
        <p>No orders yet</p>
      ) : (
        <>
          <Table striped bordered hover>
            <thead>
              <tr>
                <th>Order ID</th>
                <th>Product Name</th>
                <th>Quantity</th>
                <th>Price (Rs.)</th>
                <th>Total Price (Rs.)</th>
              </tr>
            </thead>
            <tbody>
              {orders.map((order, index) => (
                order.products.map((product, productIndex) => (
                  <tr key={`${index}-${productIndex}`}>
                    {productIndex === 0 ? (
                      <td rowSpan={order.products.length}>{order._id}</td>
                    ) : null}
                    <td>{product.name}</td>
                    <td>{product.quantity}</td>
                    <td>{product.price.toFixed(2)}</td>
                    <td>{(product.price * product.quantity).toFixed(2)}</td>
                  </tr>
                ))
              ))}
            </tbody>
          </Table>
          <div>
            <strong>Total Price:</strong> Rs. {calculateTotalPrice().toFixed(2)}
          </div>
          <Button variant="primary" onClick={handlePayment}>Make Payment</Button>
        </>
      )}
    </div>
  );
};

export default Orders;
