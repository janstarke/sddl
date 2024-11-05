import { useId, useState, Fragment } from 'react'

import { convert } from "sddl4web";
import Button from "react-bootstrap/Button";
import Form from 'react-bootstrap/Form';
import Row from 'react-bootstrap/Row';
import Alert from 'react-bootstrap/Alert';
import 'bootstrap/dist/css/bootstrap.min.css';
import { JsonView, allExpanded, darkStyles, defaultStyles } from 'react-json-view-lite';

function App() {
  const [count, setCount] = useState(0)
  const [sddl, setSddl] = useState('');
  const [sid, setSid] = useState('S-1-5-21-1004336348-1177238915-682003330-512');
  const [json, setJson] = useState(null);
  const [lastError, setLastError] = useState(null);

  function handleSddlChange(e) {
    setSddl(e.target.value);
  }

  function handleSidChange(e) {
    setSid(e.target.value);
  }

  function convertSddl() {
    try {
      setJson(convert(sddl, sid));
      setLastError(null);
    } catch (e) {
      setLastError(e);
      setJson(null);
    }
    
  }

  return (
    <>
      <div class="container py-4 px-3 mx-auto">
        <Form>
          <Form.Group className="mb-3">
            <Row className="mb-3">
              <Form.Group>
                <Form.Label>SDDL String</Form.Label>
                <Form.Control type="text" aria-describedby="sddlHelpBlock" value={sddl} onChange={handleSddlChange} />
                <Form.Text id="sddlHelpBlock" muted>
                  Place some SDDL (Security Descriptor Description Language) string
                </Form.Text>
              </Form.Group>
            </Row>

            <Row className="mb-3">
              <Form.Group>
                <Form.Label>Domain SID</Form.Label>
                <Form.Control type="text" aria-describedby="sidHelpBlock" value={sid} onChange={handleSidChange} />
                <Form.Text id="sidHelpBlock" muted>
                  Place any SID from the domain here. This is required to find the domain RID
                </Form.Text>
              </Form.Group></Row>

          </Form.Group>

          <Row className="mb-3">
          <Button id="convert" className="btn btn-primary" onClick={convertSddl}>Decode</Button>
          </Row>

          { lastError === null ? null : 
            <Row className="mb-3"><Alert variant="danger">{lastError}</Alert></Row>}

          { json === null ? null : 
          <Row className="mb-3">
          <Fragment>
            <JsonView data={json} shouldExpandNode={allExpanded} style={defaultStyles} />
          </Fragment>
          </Row> }
        </Form>
      </div>
    </>
  )
}

export default App
