import { useId, useState, Fragment } from 'react'
import reactLogo from './assets/react.svg'
import viteLogo from '/vite.svg'
import './App.css'

import { convert } from "sddl-wasm";
import Button from "react-bootstrap/Button";
import Form from 'react-bootstrap/Form';
import 'bootstrap/dist/css/bootstrap.min.css';
import { JsonView, allExpanded, darkStyles, defaultStyles } from 'react-json-view-lite';

function App() {
  const [count, setCount] = useState(0)
  const [sddl, setSddl] = useState('');
  const [json, setJson] = useState('');

  function handleChange(e) {
    setSddl(e.target.value);
    setJson(convert(sddl));
  }

  return (
    <>
      <div>
        <Form>
          <Form.Group className="mb-3">
            <Form.Label>SDDL String:</Form.Label>
            <Form.Control type="text" aria-describedby="sddlHelpBlock" value={sddl} onChange={handleChange} />
            <Form.Text id="sddlHelpBlock" muted>
              Place some SDDL (Security Descriptor Description Language) string
            </Form.Text>
          </Form.Group>
          <Button id="convert" className="btn btn-primary" onClick={() => setJson(convert(sddl))}>Decode</Button>

          <Fragment>
            <JsonView data={json} shouldExpandNode={allExpanded} style={defaultStyles} />
          </Fragment>
        </Form>
      </div>
    </>
  )
}

export default App
