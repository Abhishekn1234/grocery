import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useCart } from './ContextReducer';
import { Button } from 'react-bootstrap';
import { BsTrash } from 'react-icons/bs';
import axios from 'axios';

const Cart = () => {
  const { cart, dispatch } = useCart();
  const history = useNavigate();
 
  // Load cart items from local storage when component mounts
  useEffect(() => {
    const storedCart = JSON.parse(localStorage.getItem('cart'));
    if (storedCart) {
      dispatch({ type: 'LOAD_CART', payload: storedCart });
    }
  }, [dispatch]);

  useEffect(() => {
    // Save cart to localStorage whenever it changes
    localStorage.setItem('cart', JSON.stringify(cart));
  }, [cart]);

  const handleRemove = (productId, quantity) => {
    // Dispatch REMOVE_FROM_CART action with productId payload
    dispatch({ type: 'REMOVE_FROM_CART', payload: { productId, quantity } });
  };

  const handleCheckout = async () => {
    try {
      // Extract product details for the order
      const products = cart.map(item => ({
        productId: item.productId,
        quantity: item.quantity,
        name: item.name,
        price: item.price
      }));

      // Calculate total price
      const totalPrice = cart.reduce((total, item) => total + item.price * item.quantity, 0);

      // Send the order details to the backend
      const response = await axios.post('http://localhost:5000/orders', { products, totalPrice });

      // Handle successful order creation
      console.log('Order created:', response.data);

      // Clear cart after successful checkout
      dispatch({ type: 'CHECKOUT' });

      // Redirect to orders page or display a success message
      history('/orders');
    } catch (error) {
      console.error('Error creating order:', error);
      // Handle error, display error message, etc.
    }
  };

  // Calculate total price
  const totalPrice = Array.isArray(cart) ? cart.reduce((total, item) => total + item.price * item.quantity, 0) : 0;


  return (
    <div style={{ backgroundColor: 'orange', minHeight: '100vh', color: '#fff' }}>
      <h2>Cart</h2>
      {cart.length === 0 ? (
        <div>
          <p>Your cart is empty</p>
          <Button onClick={() => history('/')}>Go Back</Button>
        </div>
      ) : (
        <div>
          <table className="table table-striped">
            <thead>
              <tr>
                <th>Product Name</th>
                <th>Quantity</th>
                <th>Price</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {cart.map((item) => (
                <tr key={item.productId}>
                  <td>{item.name}</td>
                  <td>{item.quantity}</td>
                  <td>{item.price.toFixed(2)}</td>
                  <td>
                    {/* Pass productId and quantity to handleRemove */}
                    <Button variant="danger" onClick={() => handleRemove(item.productId, item.quantity)}>
                      <BsTrash />
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {/* Display total price */}
          <div>
            <strong>Total Price:</strong> Rs. {totalPrice.toFixed(2)}
          </div>
          <Button variant="primary" onClick={handleCheckout}>Checkout</Button>
        </div>
      )}
    </div>
  );
};

export default Cart;
