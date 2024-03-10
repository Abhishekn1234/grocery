// orderRoutes.js

const express = require('express');
const router = express.Router();
const { Order, CartItem } = require('../models/category');

// Create a new order
router.post('/orders', async (req, res) => {
  try {
    const { userId, userEmail, userName, products, totalPrice } = req.body;
    const order = new Order({ userId, userEmail, userName, products, totalPrice });
    await order.save();
    res.status(201).json(order);
  } catch (error) {
    console.error('Error creating order:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Create a new cart item
router.post('/cart', async (req, res) => {
  try {
    const { product, quantity, userEmail } = req.body;
    const cartItem = new CartItem({ product, quantity, userEmail });
    await cartItem.save();
    res.status(201).json(cartItem);
  } catch (error) {
    console.error('Error creating cart item:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Fetch cart items by user email
router.get('/cart/:email', async (req, res) => {
  try {
    const { email } = req.params;
    const cartItems = await CartItem.find({ userEmail: email });
    const itemCount = cartItems.reduce((total, item) => total + item.quantity, 0);
    res.status(200).json({ cartItems, itemCount });
  } catch (error) {
    console.error('Error fetching cart items:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Fetch orders by user email
router.get('/orders/:email', async (req, res) => {
  try {
    const { email } = req.params;
    const orders = await Order.find({ userEmail: email });
    res.status(200).json(orders);
  } catch (error) {
    console.error('Error fetching orders:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Get all orders
router.get('/orders', async (req, res) => {
  try {
    const orders = await Order.find();
    res.status(200).json(orders);
  } catch (error) {
    console.error('Error fetching orders:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Get orders by user ID
router.get('/orders/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const orders = await Order.find({ userId });
    res.status(200).json(orders);
  } catch (error) {
    console.error('Error fetching orders by user ID:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

module.exports = router;
