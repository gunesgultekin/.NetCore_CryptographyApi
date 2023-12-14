using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PUBLIC_KEY_INFRASTRUCTURE.Context;
using PUBLIC_KEY_INFRASTRUCTURE.Entities;
using System.ComponentModel;

namespace PUBLIC_KEY_INFRASTRUCTURE.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class MessagesController : ControllerBase
    {
        private DBContext _context;

        public MessagesController (DBContext context)
        {
            this._context = context;
        }

        // DELETE ALL THE MESSAGES (FILE PATHS) WITHIN THE DATABASE
        [HttpGet("DeleteAll")]
        public void deleteAll()
        {
            _context.Messages.ExecuteDelete();
        }

        // GET ALL RECEIVED FILE PATHS WITHIN THE DATABASE
        [HttpGet("getReceivedFileNames")]
        public async Task <List<string>> getReceivedFileNames()
        {
            List<Messages> files = await _context.Messages.ToListAsync();
            List<string> fileNames = new List<string>();
            for (int i=0;i<files.Count;++i)
            {
                fileNames.Add(files[i].messageBody);   

            }
            return fileNames;
        }

        // GET ALL THE INFORMATION WITHIN THE DATABASE
        [HttpGet("getAll")]
        public async Task<ActionResult<List<Messages>>> getAll()
        {
            List<Messages> list = await _context.Messages.ToListAsync();
            if (list.Count == 0 || list == null)
            {
                return BadRequest("No Messages found in mesaages channel");

            }
            return list;

        }
    }
}
