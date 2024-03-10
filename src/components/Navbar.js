import React, { useEffect, useState } from 'react';
import { Navbar, Container, Nav, Button, Badge } from 'react-bootstrap';
import { Link } from 'react-router-dom';
import { FaShoppingCart, FaUser, FaListAlt, FaBoxes, FaUserAlt, FaClipboardList } from 'react-icons/fa'; // Import icons

export default function CustomNavbar({ isLoggedIn, setIsLoggedIn }) {
  const [cartItemCount, setCartItemCount] = useState(0);

  useEffect(() => {
    // Retrieve cart items from localStorage
    const savedCart = JSON.parse(localStorage.getItem('cart')) || [];
    // Calculate total number of items in the cart
    let totalItems = 0;
    savedCart.forEach(item => {
      totalItems += item.quantity;
    });
    setCartItemCount(totalItems);
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('token');
    setIsLoggedIn(false);
  };

  return (
    <Navbar variant="dark" expand="lg" style={{ backgroundColor: 'blue', color: "#fff" }}>
      <Container>
        <Navbar.Brand as={Link} to="/">Grocery Store</Navbar.Brand>
        <Navbar.Toggle aria-controls="navbar-nav" />
        <Navbar.Collapse id="navbar-nav">
          <Nav className="ms-auto"> {/* Use ms-auto to align links to the right */}
            {isLoggedIn ? (
              <>
                <Nav.Link as={Link} to="/cart" style={{ color: "white" }}>
                  <FaShoppingCart style={{ marginRight: '5px' }} />
                  Cart{' '}
                  {cartItemCount > 0 && <Badge bg="secondary">{cartItemCount}</Badge>}
                </Nav.Link>
                <Nav.Link as={Link} to="/categories" style={{ color: "white" }}>
                  <FaListAlt style={{ marginRight: '5px' }} />
                  Categories
                </Nav.Link>
                <Nav.Link as={Link} to="/products" style={{ color: "white" }}>
                  <FaBoxes style={{ marginRight: '5px' }} />
                  Products
                </Nav.Link>
                <Nav.Link as={Link} to="/profile" style={{ color: "white" }}>
                  <FaUserAlt style={{ marginRight: '5px' }} />
                  Profile
                </Nav.Link>
                <Nav.Link as={Link} to="/orders" style={{ color: "white" }}>
                  <FaClipboardList style={{ marginRight: '5px' }} />
                  Orders
                </Nav.Link>
                <Button variant="outline-light" onClick={handleLogout}>
                  <FaUser style={{ marginRight: '5px' }} />
                  Logout
                </Button>
              </>
            ) : (
              <>
                <Nav.Link as={Link} to="/login" style={{ color: "white" }}>
                  <FaUser style={{ marginRight: '5px' }} />
                  Login
                </Nav.Link>
                <Nav.Link as={Link} to="/signup" style={{ color: "white" }}>
                  <FaUser style={{ marginRight: '5px' }} />
                  Signup
                </Nav.Link>
              </>
            )}
          </Nav>
        </Navbar.Collapse>
      </Container>
    </Navbar>
  );
}
